package corenet

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type clientListenerSession struct {
	conn      net.Conn
	address   string
	channel   string
	tlsConfig *tls.Config

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
	conn, err := tls.Dial("tcp", s.address, s.tlsConfig)
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := json.NewEncoder(conn).Encode(&BridgeRequest{Type: Dial, Payload: s.channel}); err != nil {
		conn.Close()
		s.Close()
		return nil, err
	}

	resp := BridgeResponse{}
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
	conn, err := tls.Dial("tcp", s.address, s.tlsConfig)
	if err != nil {
		s.Close()
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(&BridgeRequest{Type: Info, Payload: s.channel}); err != nil {
		s.Close()
		return nil, err
	}
	resp := BridgeResponse{}
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

func newClientListenerBasedSession(address, channel string, tlsConfig *tls.Config) (Session, error) {
	probeConn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(probeConn).Encode(&BridgeRequest{Type: Nop, Payload: channel}); err != nil {
		probeConn.Close()
		return nil, err
	}

	session := clientListenerSession{conn: probeConn, address: address, channel: channel, tlsConfig: tlsConfig, close: make(chan struct{})}
	go func() {
		probeConn.Read(make([]byte, 1))
		session.Close()
	}()
	return &session, nil
}

func newClientListenerAdapter(address, channel string, TLSConfig *tls.Config) (ListenerAdapter, error) {
	controlConn, err := tls.Dial("tcp", address, TLSConfig)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(controlConn).Encode(BridgeRequest{Type: Bind, Payload: channel}); err != nil {
		controlConn.Close()
		return nil, err
	}
	resp := BridgeResponse{}
	if err := json.NewDecoder(controlConn).Decode(&resp); err != nil {
		controlConn.Close()
		return nil, err
	}
	if !resp.Success {
		controlConn.Close()
		return nil, fmt.Errorf("remote error: %v", resp.Payload)
	}
	return WithListenerReverseConn(controlConn, func() (net.Conn, error) {
		conn, err := tls.Dial("tcp", address, TLSConfig)
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(BridgeRequest{Type: Serve, Payload: channel}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, []string{fmt.Sprintf("ttf://%s?channel=%s", address, channel)}), nil
}

type listenerBasedBridgeProtocol struct {
	serveChan   chan serveContext
	mu          sync.Mutex
	connChanMap map[string]chan net.Conn
}

func (p *listenerBasedBridgeProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
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

func (p *listenerBasedBridgeProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
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

func (p *listenerBasedBridgeProtocol) serveListener() {
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

func (p *listenerBasedBridgeProtocol) ServeChannel() chan serveContext { return p.serveChan }

// CreateBridgeListenerBasedFallback provides a bridge protocol for the bridge server.
func CreateBridgeListenerBasedFallback() BridgeProtocol {
	p := listenerBasedBridgeProtocol{connChanMap: make(map[string]chan net.Conn), serveChan: make(chan serveContext)}
	go p.serveListener()
	return &p
}
