package corenet

import (
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/xtaci/smux"
)

// smuxConnListener is a wrapper to convert a smux.Session as a listener.
type smuxConnListener struct {
	*smux.Session
}

func (l *smuxConnListener) Accept() (net.Conn, error) {
	return l.Session.AcceptStream()
}

func (l *smuxConnListener) Addr() net.Addr {
	return l.LocalAddr()
}

// UseSmuxRelayProtocol provides a relay protocol based on kcp.
func UseSmuxRelayProtocol() RelayProtocol {
	return &smuxRelayProtocol{}
}

type smuxRelayProtocol struct {
}

func (p *smuxRelayProtocol) ServeChannel() chan serveContext { return nil }

func (p *smuxRelayProtocol) ExtractIdentity(Conn net.Conn) (*RelayPeerContext, error) {
	return extractIdentityFromTLSConn(Conn)
}

func (p *smuxRelayProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
	connSession, err := smux.Client(newBufferedConn(ListenerConn), nil)
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
		addr:           fmt.Sprintf("smux://localhost?channel=%s", Channel),
	}, nil
}

func (p *smuxRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	connSession, err := smux.Server(newBufferedConn(ClientConn), nil)
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
			if err := json.NewEncoder(stream).Encode(RelayResponse{Success: true}); err != nil {
				stream.Close()
				return nil, err
			}
			return stream, nil
		},
		isDialerClosed: connSession.IsClosed,
		closer:         connSession.Close,
		addr:           fmt.Sprintf("smux://%s", ClientConn.RemoteAddr().String()),
	}, nil
}

func CreateSmuxListenerAdapter(dialer func() (net.Conn, error), url, channel string) (ListenerAdapter, error) {
	conn, err := dialer()
	if err != nil {
		return nil, err
	}
	if _, err := doClientHandshake(conn, &RelayRequest{Type: Bind, Payload: channel}); err != nil {
		conn.Close()
		return nil, err
	}
	server, err := smux.Server(newBufferedConn(conn), nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return WithListener(&smuxConnListener{server}, []string{url}), nil
}

func getChannelInfo(dialer func() (net.Conn, error), channel string) (*SessionInfo, error) {
	conn, err := dialer()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := doClientHandshake(conn, &RelayRequest{Type: Info, Payload: channel})
	if err != nil {
		return nil, err
	}
	if len(resp.SessionInfo) == 0 {
		return nil, fmt.Errorf("no available session info")
	}
	return &resp.SessionInfo[0], nil
}

func newSmuxClientSession(dialer func() (net.Conn, error), channel string) (Session, error) {
	conn, err := dialer()
	if err != nil {
		return nil, err
	}

	if _, err := doClientHandshake(conn, &RelayRequest{Type: Dial, Payload: channel}); err != nil {
		conn.Close()
		return nil, err
	}

	connSession, err := smux.Client(newBufferedConn(conn), nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	sessionInfo, err := getChannelInfo(dialer, channel)
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
			resp := RelayResponse{}
			if err := json.NewDecoder(stream).Decode(&resp); err != nil {
				stream.Close()
				return nil, err
			}
			if !resp.Success {
				stream.Close()
				return nil, fmt.Errorf("application error: %s", resp.Payload)
			}
			return createTrackConn(stream, "corenet_client_smux_active_connections"), nil
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
