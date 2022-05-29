package corenet

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
)

type kcpListener struct {
	*kcp.Listener
	config *KCPConfig
}

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

func (p *kcpRelayProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
	connSession, err := smux.Client(ListenerConn, nil)
	if err != nil {
		return nil, err
	}
	session := &clientSession{
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
	}
	return session, nil
}

func (p *kcpRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	connSession, err := smux.Server(ClientConn, nil)
	if err != nil {
		return nil, err
	}
	session := &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := connSession.AcceptStream()
			if err != nil {
				return nil, err
			}
			return stream, nil
		},
	}
	return session, nil
}

func newKcpListenerAdapter(Addr, Channel string, TLSConfig *tls.Config, KCPConfig *KCPConfig) (ListenerAdapter, error) {
	conn, err := createKCPConnection(Addr, TLSConfig, KCPConfig)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(conn).Encode(RelayRequest{Type: Bind, Payload: Channel}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, err
	}
	if !resp.Success {
		conn.Close()
		return nil, fmt.Errorf("remote error: %v", resp.Payload)
	}
	server, err := smux.Server(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return WithListener(&kcpConnListener{server}, []string{fmt.Sprintf("kcpf://%s?channel=%s", Addr, Channel)}), nil
}

type clientKcpSession struct {
	conn        *smux.Session
	sessionInfo *SessionInfo

	id       string
	mu       sync.Mutex
	isClosed bool
	close    chan struct{}
}

func (s *clientKcpSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	s.conn.Close()
	close(s.close)
	return nil
}

func (s *clientKcpSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return true
	}
	if s.conn.IsClosed() {
		s.isClosed = true
	}
	return s.isClosed
}

func (s *clientKcpSession) Done() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.close
}

func (s *clientKcpSession) Dial() (net.Conn, error) {
	stream, err := s.conn.OpenStream()
	if err != nil {
		s.Close()
		return nil, err
	}
	return createTrackConn(stream, "client_kcp_active_connections"), nil
}

func (s *clientKcpSession) Info() (*SessionInfo, error) {
	if s.sessionInfo == nil {
		return nil, fmt.Errorf("not supported")
	}
	return s.sessionInfo, nil
}

func (s *clientKcpSession) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *clientKcpSession) SetID(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = v
}

func getKcpChannelInfo(address, channel string, tlsConfig *tls.Config, KCPConfig *KCPConfig) (*SessionInfo, error) {
	conn, err := createKCPConnection(address, tlsConfig, KCPConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(&RelayRequest{Type: Info, Payload: channel}); err != nil {
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Payload)
	}
	return &resp.SessionInfo, nil
}

func newClientKcpBasedSession(address, channel string, tlsConfig *tls.Config, kcpConfig *KCPConfig) (Session, error) {
	conn, err := createKCPConnection(address, tlsConfig, kcpConfig)
	if err != nil {
		return nil, err
	}

	if err := json.NewEncoder(conn).Encode(&RelayRequest{Type: Dial, Payload: channel}); err != nil {
		conn.Close()
		return nil, err
	}

	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, err
	}
	if !resp.Success {
		conn.Close()
		return nil, fmt.Errorf(resp.Payload)
	}

	connSession, err := smux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	session := &clientKcpSession{conn: connSession, close: make(chan struct{}), isClosed: false}

	sessionInfo, err := getKcpChannelInfo(address, channel, tlsConfig, kcpConfig)
	if err != nil {
		log.Printf("Failed to obtain session info for %s: %v", channel, err)
	}
	session.sessionInfo = sessionInfo
	return session, nil
}
