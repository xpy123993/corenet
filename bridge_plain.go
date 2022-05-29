package corenet

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type clientListenerSession struct {
	conn             net.Conn
	channel          string
	underlyingDialer func() (net.Conn, error)

	id       string
	mu       sync.Mutex
	isClosed bool
	close    chan struct{}
}

func (s *clientListenerSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	close(s.close)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *clientListenerSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isClosed
}

func (s *clientListenerSession) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *clientListenerSession) SetID(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = v
}

func (s *clientListenerSession) OpenConnection() (net.Conn, error) {
	conn, err := s.underlyingDialer()
	if err != nil {
		s.Close()
		return nil, err
	}
	if _, err := doClientHandshake(conn, &RelayRequest{Type: Dial, Payload: s.channel}); err != nil {
		conn.Close()
		return nil, err
	}
	return createTrackConn(conn, "corenet_client_plain_active_connections"), nil
}

func (s *clientListenerSession) Info() (*SessionInfo, error) {
	conn, err := s.underlyingDialer()
	if err != nil {
		s.Close()
		return nil, err
	}
	defer conn.Close()
	resp, err := doClientHandshake(conn, &RelayRequest{Type: Info, Payload: s.channel})
	if err != nil {
		return nil, err
	}
	return &resp.SessionInfo, nil
}

func (s *clientListenerSession) Done() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.close
}

func newClientListenerBasedSession(channel string, underlyingDialer func() (net.Conn, error)) (Session, error) {
	probeConn, err := underlyingDialer()
	if err != nil {
		return nil, err
	}
	session := clientListenerSession{conn: probeConn, underlyingDialer: underlyingDialer, channel: channel, close: make(chan struct{})}
	go func() {
		doClientHandshake(probeConn, &RelayRequest{Type: Nop, Payload: channel})
		session.Close()
	}()
	return &session, nil
}

func newClientListenerAdapter(address, channel string, underlyingDialer func() (net.Conn, error)) (ListenerAdapter, error) {
	controlConn, err := underlyingDialer()
	if err != nil {
		return nil, err
	}
	if _, err := doClientHandshake(controlConn, &RelayRequest{Type: Bind, Payload: channel}); err != nil {
		controlConn.Close()
		return nil, err
	}
	return WithListenerReverseConn(controlConn, func() (net.Conn, error) {
		conn, err := underlyingDialer()
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(RelayRequest{Type: Serve, Payload: channel}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, []string{fmt.Sprintf("ttf://%s?channel=%s", address, channel)}), nil
}

type listenerBasedRelayProtocol struct {
	serveChan   chan serveContext
	mu          sync.Mutex
	connChanMap map[string]chan net.Conn
}

func (p *listenerBasedRelayProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
	p.mu.Lock()
	connChan, exist := p.connChanMap[Channel]
	if !exist {
		p.connChanMap[Channel] = make(chan net.Conn)
		connChan = p.connChanMap[Channel]
	}
	p.mu.Unlock()
	if _, err := ListenerConn.Write([]byte{Nop}); err != nil {
		ListenerConn.Close()
		return nil, err
	}
	session := clientSession{dialer: func() (net.Conn, error) {
		if _, err := ListenerConn.Write([]byte{Dial}); err != nil {
			return nil, err
		}
		remoteConn, ok := <-connChan
		if ok {
			return remoteConn, nil
		}
		return nil, io.EOF
	}, infoFn: func() (*SessionInfo, error) {
		sessionInfo, err := getSessionInfo(ListenerConn)
		if err != nil {
			return nil, err
		}
		return sessionInfo, nil
	}, isClosed: false, done: make(chan struct{}), closer: ListenerConn.Close, isDialerClosed: func() bool {
		if _, err := ListenerConn.Write([]byte{Nop}); err != nil {
			return true
		}
		return false
	}}
	return &session, nil
}

type closableConn struct {
	net.Conn

	mu       sync.Mutex
	done     chan struct{}
	isClosed bool
}

func (c *closableConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	c.isClosed = true
	close(c.done)
	return c.Conn.Close()
}

func (c *closableConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}

func (p *listenerBasedRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	conn := &closableConn{Conn: ClientConn, done: make(chan struct{}), isClosed: false}
	returned := false
	session := clientSession{dialer: func() (net.Conn, error) {
		if conn.IsClosed() {
			return nil, io.EOF
		}
		p.mu.Lock()
		if returned {
			p.mu.Unlock()
			<-conn.done
			return nil, io.EOF
		}
		returned = true
		defer p.mu.Unlock()
		return conn, nil
	}, isClosed: false, done: make(chan struct{}), closer: conn.Close}
	return &session, nil
}

func (p *listenerBasedRelayProtocol) serveListener() {
	go func() {
		for {
			serve, ok := <-p.serveChan
			if !ok {
				for _, c := range p.connChanMap {
					close(c)
				}
				close(p.serveChan)
				return
			}
			go func(ctx *serveContext) {
				p.mu.Lock()
				connChan, exist := p.connChanMap[ctx.channel]
				if !exist {
					p.connChanMap[ctx.channel] = make(chan net.Conn)
					connChan = p.connChanMap[ctx.channel]
				}
				p.mu.Unlock()
				connChan <- ctx.conn
			}(&serve)
		}
	}()
}

func (p *listenerBasedRelayProtocol) ServeChannel() chan serveContext { return p.serveChan }
func (p *listenerBasedRelayProtocol) ExtractIdentity(Conn net.Conn) (*RelayPeerContext, error) {
	return extractIdentityFromTLSConn(Conn)
}

// UsePlainRelayProtocol provides a relay protocol for the relay server.
func UsePlainRelayProtocol() RelayProtocol {
	p := listenerBasedRelayProtocol{connChanMap: make(map[string]chan net.Conn), serveChan: make(chan serveContext)}
	go p.serveListener()
	return &p
}
