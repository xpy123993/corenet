package corenet

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// kcpListener is a wrapper to accept kcp connection and apply the corresponding config.
type kcpListener struct {
	*kcp.Listener
	config *KCPConfig
}

// CreateRelayKCPListener creates a KCP listener for the relay service.
func CreateRelayKCPListener(Addr string, TLSConfig *tls.Config, KCPConfig *KCPConfig) (net.Listener, error) {
	lis, err := kcp.ListenWithOptions(Addr, nil, KCPConfig.DataShard, KCPConfig.ParityShard)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(&kcpListener{lis, KCPConfig}, TLSConfig), nil
}

func (lis *kcpListener) Accept() (net.Conn, error) {
	conn, err := lis.AcceptKCP()
	if err != nil {
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetMtu(lis.config.MTU)
	conn.SetNoDelay(lis.config.NoDelay, lis.config.Interval, lis.config.Resend, lis.config.NoCongestion)
	conn.SetWindowSize(lis.config.SndWnd, lis.config.RcvWnd)
	return conn, nil
}

func createKCPConnection(Addr string, TLSConfig *tls.Config, kcpConfig *KCPConfig) (net.Conn, error) {
	conn, err := kcp.DialWithOptions(Addr, nil, kcpConfig.DataShard, kcpConfig.ParityShard)
	if err != nil {
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetMtu(kcpConfig.MTU)
	conn.SetNoDelay(kcpConfig.NoDelay, kcpConfig.Interval, kcpConfig.Resend, kcpConfig.NoCongestion)
	conn.SetWindowSize(kcpConfig.SndWnd, kcpConfig.RcvWnd)
	return tls.Client(conn, TLSConfig), nil
}

// kcpConnListener is a wrapper to convert a smux.Session as a listener.
type kcpConnListener struct {
	*smux.Session
}

func (l *kcpConnListener) Accept() (net.Conn, error) {
	return l.Session.AcceptStream()
}

func (l *kcpConnListener) Addr() net.Addr {
	return l.LocalAddr()
}

// UseKCPRelayProtocol provides a relay protocol based on kcp.
func UseKCPRelayProtocol() RelayProtocol {
	return &kcpRelayProtocol{}
}

type kcpRelayProtocol struct {
}

func (p *kcpRelayProtocol) ServeChannel() chan serveContext { return nil }

func (p *kcpRelayProtocol) ExtractIdentity(Conn net.Conn) (*RelayPeerContext, error) {
	return extractIdentityFromTLSConn(Conn)
}

func (p *kcpRelayProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
	connSession, err := smux.Client(ListenerConn, nil)
	if err != nil {
		return nil, err
	}
	return &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := connSession.OpenStream()
			if err != nil {
				return nil, err
			}
			if _, err := stream.Write([]byte{Dial}); err != nil {
				stream.Close()
				return nil, err
			}
			return stream, nil
		},
		infoFn: func() (*SessionInfo, error) {
			stream, err := connSession.OpenStream()
			if err != nil {
				return nil, err
			}
			defer stream.Close()
			return getSessionInfo(stream)
		},
		isDialerClosed: connSession.IsClosed,
		closer:         connSession.Close,
		addr:           fmt.Sprintf("ktf://localhost?channel=%s", Channel),
	}, nil
}

func (p *kcpRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	connSession, err := smux.Server(ClientConn, nil)
	if err != nil {
		return nil, err
	}
	return &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := connSession.AcceptStream()
			if err != nil {
				return nil, err
			}
			return stream, nil
		},
		isDialerClosed: connSession.IsClosed,
		closer:         connSession.Close,
		addr:           fmt.Sprintf("ktf://%s", ClientConn.RemoteAddr().String()),
	}, nil
}

func newKcpListenerAdapter(Addr, Channel string, TLSConfig *tls.Config, KCPConfig *KCPConfig) (ListenerAdapter, error) {
	conn, err := createKCPConnection(Addr, TLSConfig, KCPConfig)
	if err != nil {
		return nil, err
	}
	if _, err := doClientHandshake(conn, &RelayRequest{Type: Bind, Payload: Channel}); err != nil {
		conn.Close()
		return nil, err
	}
	server, err := smux.Server(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return WithListener(&kcpConnListener{server}, []string{fmt.Sprintf("ktf://%s?channel=%s", Addr, Channel)}), nil
}

func getKcpChannelInfo(address, channel string, tlsConfig *tls.Config, KCPConfig *KCPConfig) (*SessionInfo, error) {
	conn, err := createKCPConnection(address, tlsConfig, KCPConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := doClientHandshake(conn, &RelayRequest{Type: Info, Payload: channel})
	if err != nil {
		return nil, err
	}
	return &resp.SessionInfo, nil
}

func newClientKcpBasedSession(address, channel string, tlsConfig *tls.Config, kcpConfig *KCPConfig) (Session, error) {
	conn, err := createKCPConnection(address, tlsConfig, kcpConfig)
	if err != nil {
		return nil, err
	}

	if _, err := doClientHandshake(conn, &RelayRequest{Type: Dial, Payload: channel}); err != nil {
		conn.Close()
		return nil, err
	}

	connSession, err := smux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	sessionInfo, err := getKcpChannelInfo(address, channel, tlsConfig, kcpConfig)
	if err != nil {
		log.Printf("Failed to obtain session info for %s: %v", channel, err)
		sessionInfo = nil
	}
	return &clientSession{
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := connSession.OpenStream()
			if err != nil {
				return nil, err
			}
			return createTrackConn(stream, "corenet_client_kcp_active_connections"), nil
		},
		infoFn: func() (*SessionInfo, error) {
			if sessionInfo != nil {
				return sessionInfo, nil
			}
			return nil, fmt.Errorf("not supported")
		},
		isDialerClosed: connSession.IsClosed,
		closer:         connSession.Close,
		done:           make(chan struct{}),
	}, nil
}
