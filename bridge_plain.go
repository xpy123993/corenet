package corenet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

func newReverseSession(conn net.Conn, connChan chan net.Conn) (Session, error) {
	if _, err := conn.Write([]byte{Nop}); err != nil {
		conn.Close()
		return nil, err
	}
	session := clientSession{dialer: func() (net.Conn, error) {
		if _, err := conn.Write([]byte{Dial}); err != nil {
			return nil, err
		}
		remoteConn, ok := <-connChan
		if ok {
			return remoteConn, nil
		}
		return nil, io.EOF
	}, isClosed: false, done: make(chan struct{})}
	return &session, nil
}

func newClientFallbackSession(address, channel string, tlsConfig *tls.Config) (Session, error) {
	return &clientSession{dialer: func() (net.Conn, error) {
		conn, err := tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(&BridgeRequest{Type: Dial, Payload: channel}); err != nil {
			conn.Close()
			return nil, err
		}

		resp := BridgeResponse{}
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			conn.Close()
			return nil, err
		}
		if !resp.Success {
			conn.Close()
			return nil, fmt.Errorf(resp.Payload)
		}
		return conn, nil
	}, isClosed: false, done: make(chan struct{})}, nil
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
	return WithListenerReverseConn(controlConn, func() (net.Conn, error) {
		conn, err := tls.Dial("tcp", resp.Payload, TLSConfig)
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(BridgeRequest{Type: Bind, Payload: channel}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, []string{fmt.Sprintf("ttf://%s", address)}), nil
}

type listenerBasedBridgeProtocol struct {
	mu          sync.Mutex
	connChanMap map[string]chan net.Conn
}

func (p *listenerBasedBridgeProtocol) BridgeSession(Channel string, ClientConn net.Conn, ListenerSession Session) error {
	remoteConn, err := ListenerSession.Dial()
	if err != nil {
		json.NewEncoder(ClientConn).Encode(BridgeResponse{Success: false, Payload: "Connection is reset"})
		return fmt.Errorf("channel connection is reset")
	}
	defer remoteConn.Close()

	if err := json.NewEncoder(ClientConn).Encode(BridgeResponse{Success: true}); err != nil {
		return err
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	go func() { io.Copy(ClientConn, remoteConn); cancelFn() }()
	go func() { io.Copy(remoteConn, ClientConn); cancelFn() }()
	<-ctx.Done()
	return nil
}

func (p *listenerBasedBridgeProtocol) InitSession(Channel string, ListenerConn net.Conn) (Session, error) {
	p.mu.Lock()
	connChan, exist := p.connChanMap[Channel]
	if !exist {
		p.connChanMap[Channel] = make(chan net.Conn)
		connChan = p.connChanMap[Channel]
	}
	p.mu.Unlock()
	return newReverseSession(ListenerConn, connChan)
}

func (p *listenerBasedBridgeProtocol) serveListener(lis net.Listener) {
	go func() {
		for {
			bridgeConn, err := lis.Accept()
			if err != nil {
				for _, c := range p.connChanMap {
					close(c)
				}
				lis.Close()
				return
			}
			go func(bridgeConn net.Conn) {
				req := BridgeRequest{}
				if err := json.NewDecoder(bridgeConn).Decode(&req); err != nil {
					bridgeConn.Close()
					return
				}
				p.mu.Lock()
				connChan, exist := p.connChanMap[req.Payload]
				if !exist {
					p.connChanMap[req.Payload] = make(chan net.Conn)
					connChan = p.connChanMap[req.Payload]
				}
				p.mu.Unlock()
				connChan <- bridgeConn
			}(bridgeConn)
		}
	}()
}

// CreateBridgeListenerBasedFallback provides a bridge protocol for the bridge server.
func CreateBridgeListenerBasedFallback(lis net.Listener) BridgeProtocol {
	p := listenerBasedBridgeProtocol{connChanMap: make(map[string]chan net.Conn)}
	go p.serveListener(lis)
	return &p
}
