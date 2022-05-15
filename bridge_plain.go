package corenet

import (
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
	return WithReverseListener(controlConn, func() (net.Conn, error) {
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

// CreateBridgeListenerBasedFallback provides a bridge protocol for the bridge server.
func CreateBridgeListenerBasedFallback(lis net.Listener) func(string, net.Conn) (Session, error) {
	mu := sync.Mutex{}
	connChanMap := make(map[string]chan net.Conn)
	go func() {
		for {
			bridgeConn, err := lis.Accept()
			if err != nil {
				for _, c := range connChanMap {
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
				mu.Lock()
				connChan, exist := connChanMap[req.Payload]
				if !exist {
					connChanMap[req.Payload] = make(chan net.Conn)
					connChan = connChanMap[req.Payload]
				}
				mu.Unlock()
				connChan <- bridgeConn
			}(bridgeConn)
		}
	}()
	return func(s string, c net.Conn) (Session, error) {
		mu.Lock()
		connChan, exist := connChanMap[s]
		if !exist {
			connChanMap[s] = make(chan net.Conn)
			connChan = connChanMap[s]
		}
		mu.Unlock()
		return newReverseSession(c, connChan)
	}
}
