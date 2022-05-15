package corenet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/lucas-clemente/quic-go"
)

type quicConn struct {
	quic.Stream
	Connection quic.Connection
}

func (c *quicConn) LocalAddr() net.Addr  { return c.Connection.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.Connection.RemoteAddr() }
func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

type quicListener struct {
	lis quic.Listener
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.lis.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicConn{Stream: stream, Connection: conn}, nil
}

func (l *quicListener) Addr() net.Addr { return l.lis.Addr() }
func (l *quicListener) Close() error   { return l.lis.Close() }

type quicConnListener struct {
	quic.Connection
}

func (l *quicConnListener) Accept() (net.Conn, error) {
	stream, err := l.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicConn{Stream: stream, Connection: l.Connection}, nil
}

func (l *quicConnListener) Addr() net.Addr { return l.Connection.LocalAddr() }
func (l *quicConnListener) Close() error   { return l.CloseWithError(0, "") }

// CreateBridgeQuicFallback provides a bridge protocol based on quic.
func CreateBridgeQuicFallback() BridgeProtocol {
	return &quicBridgeProtocol{}
}

type quicBridgeProtocol struct {
}

func (p *quicBridgeProtocol) InitSession(Channel string, ListenerConn net.Conn) (Session, error) {
	packetConn, ok := ListenerConn.(*quicConn)
	if !ok {
		return nil, fmt.Errorf("expect session connection to be quicConn")
	}
	return &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := packetConn.Connection.OpenStream()
			if err != nil {
				return nil, err
			}
			return &quicConn{Stream: stream, Connection: packetConn.Connection}, nil
		},
	}, nil
}

func (p *quicBridgeProtocol) BridgeSession(Channel string, ClientConn net.Conn, ListenerSession Session) error {
	if err := json.NewEncoder(ClientConn).Encode(BridgeResponse{Success: true}); err != nil {
		return err
	}

	clientQuicConn, ok := ClientConn.(*quicConn)
	if !ok {
		return fmt.Errorf("expect client connection to be quicConn")
	}
	for {
		clientConn, err := clientQuicConn.Connection.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		go func(clientConn quic.Stream) {
			defer func() {
				clientConn.CancelRead(1)
				clientConn.Close()
			}()
			listenerConn, err := ListenerSession.Dial()
			if err != nil {
				return
			}
			defer listenerConn.Close()
			ctx, cancelFn := context.WithCancel(context.Background())
			go func() { io.Copy(clientConn, listenerConn); cancelFn() }()
			go func() { io.Copy(listenerConn, clientConn); cancelFn() }()
			<-ctx.Done()
		}(clientConn)

	}
}

// CreateBridgeServeListener returns the listener that can be used for bridge server serving.
func CreateBridgeServeListener(Addr string, TLSConfig *tls.Config, QuicConfig *quic.Config) (net.Listener, error) {
	lis, err := quic.ListenAddr(Addr, TLSConfig, QuicConfig)
	if err != nil {
		return nil, err
	}
	return &quicListener{lis}, nil
}

func newQuicListenerAdapter(Addr, Channel string, TLSConfig *tls.Config, QuicConfig *quic.Config) (ListenerAdapter, error) {
	conn, err := quic.DialAddr(Addr, TLSConfig, QuicConfig)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(stream).Encode(BridgeRequest{Type: Bind, Payload: Channel}); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	resp := BridgeResponse{}
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	return WithListener(&quicConnListener{conn}, []string{fmt.Sprintf("quicf://%s", Addr)}), nil
}

func newQuicClientSession(address, channel string, tlsConfig *tls.Config) (Session, error) {
	conn, err := quic.DialAddr(address, tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}

	if err := json.NewEncoder(stream).Encode(&BridgeRequest{Type: Dial, Payload: channel}); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}

	resp := BridgeResponse{}
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	if !resp.Success {
		conn.CloseWithError(1, err.Error())
		return nil, fmt.Errorf(resp.Payload)
	}

	return &clientSession{dialer: func() (net.Conn, error) {
		stream, err := conn.OpenStream()
		if err != nil {
			return nil, err
		}
		if _, err := stream.Write([]byte{Dial}); err != nil {
			stream.CancelRead(1)
			stream.Close()
			return nil, err
		}
		return &quicConn{Stream: stream, Connection: conn}, nil
	}, isClosed: false, done: make(chan struct{})}, nil
}
