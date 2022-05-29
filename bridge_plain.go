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

func (s *clientListenerSession) Dial() (net.Conn, error) {
	conn, err := s.underlyingDialer()
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := json.NewEncoder(conn).Encode(&RelayRequest{Type: Dial, Payload: s.channel}); err != nil {
		conn.Close()
		s.Close()
		return nil, err
	}

	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		s.Close()
		return nil, err
	}
	if !resp.Success {
		conn.Close()
		return nil, fmt.Errorf(resp.Payload)
	}
	return createTrackConn(conn, "client_plain_active_connections"), nil
}

func (s *clientListenerSession) Info() (*SessionInfo, error) {
	conn, err := s.underlyingDialer()
	if err != nil {
		s.Close()
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(&RelayRequest{Type: Info, Payload: s.channel}); err != nil {
		s.Close()
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		s.Close()
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Payload)
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
	if err := json.NewEncoder(probeConn).Encode(&RelayRequest{Type: Nop, Payload: channel}); err != nil {
		probeConn.Close()
		return nil, err
	}

	session := clientListenerSession{conn: probeConn, underlyingDialer: underlyingDialer, channel: channel, close: make(chan struct{})}
	go func() {
		probeConn.Read(make([]byte, 1))
		session.Close()
	}()
	go func() {
		<-session.Done()
		probeConn.Close()
	}()
	return &session, nil
}

func newClientListenerAdapter(address, channel string, underlyingDialer func() (net.Conn, error)) (ListenerAdapter, error) {
	controlConn, err := underlyingDialer()
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(controlConn).Encode(RelayRequest{Type: Bind, Payload: channel}); err != nil {
		controlConn.Close()
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(controlConn).Decode(&resp); err != nil {
		controlConn.Close()
		return nil, err
	}
	if !resp.Success {
		controlConn.Close()
		return nil, fmt.Errorf("remote error: %v", resp.Payload)
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
	}, isClosed: false, done: make(chan struct{})}
	go func() {
		<-session.done
		ListenerConn.Close()
	}()
	return &session, nil
}

func (p *listenerBasedRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	p.mu.Lock()
	clientConnectionUsed := false
	p.mu.Unlock()
	session := clientSession{dialer: func() (net.Conn, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if clientConnectionUsed {
			return nil, io.EOF
		}
		clientConnectionUsed = true
		return ClientConn, nil
	}, isClosed: false, done: make(chan struct{})}
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

// UsePlainRelayProtocol provides a relay protocol for the relay server.
func UsePlainRelayProtocol() RelayProtocol {
	p := listenerBasedRelayProtocol{connChanMap: make(map[string]chan net.Conn), serveChan: make(chan serveContext)}
	go p.serveListener()
	return &p
}
