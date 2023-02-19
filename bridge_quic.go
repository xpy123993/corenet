package corenet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
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

// UseQuicRelayProtocol provides a relay protocol based on quic.
func UseQuicRelayProtocol() RelayProtocol {
	return &quicRelayProtocol{}
}

type quicRelayProtocol struct {
}

func (p *quicRelayProtocol) InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error) {
	packetConn, ok := ListenerConn.(*quicConn)
	if !ok {
		return nil, fmt.Errorf("expect session connection to be quicConn")
	}
	session := &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := packetConn.Connection.OpenStream()
			if err != nil {
				return nil, err
			}
			if _, err := stream.Write([]byte{Dial}); err != nil {
				stream.CancelRead(0)
				stream.Close()
				return nil, err
			}
			return &quicConn{Stream: stream, Connection: packetConn.Connection}, nil
		},
		infoFn: func() (*SessionInfo, error) {
			stream, err := packetConn.Connection.OpenStream()
			if err != nil {
				return nil, err
			}
			conn := &quicConn{Stream: stream, Connection: packetConn.Connection}
			defer conn.Close()
			return getSessionInfo(conn)
		},
		closer:         func() error { return packetConn.Connection.CloseWithError(1, "") },
		isDialerClosed: func() bool { return packetConn.Connection.Context().Err() != nil },
		addr:           fmt.Sprintf("quicf://localhost?channel=%s", Channel),
	}
	return session, nil
}

func (p *quicRelayProtocol) InitClientSession(ClientConn net.Conn) (Session, error) {
	packetConn, ok := ClientConn.(*quicConn)
	if !ok {
		return nil, fmt.Errorf("expect session connection to be quicConn")
	}
	session := &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := packetConn.Connection.AcceptStream(packetConn.Context())
			if err != nil {
				return nil, err
			}
			if err := json.NewDecoder(stream).Decode(new(RelayRequest)); err != nil {
				stream.CancelRead(0)
				stream.Close()
				return nil, err
			}
			if err := json.NewEncoder(stream).Encode(RelayResponse{Success: true}); err != nil {
				stream.CancelRead(0)
				stream.Close()
				return nil, err
			}
			return &quicConn{Stream: stream, Connection: packetConn.Connection}, nil
		},
		closer:         func() error { return packetConn.Connection.CloseWithError(1, "") },
		isDialerClosed: func() bool { return packetConn.Connection.Context().Err() != nil },
		addr:           fmt.Sprintf("quicf://%s", ClientConn.RemoteAddr().String()),
	}
	return session, nil
}

func (p *quicRelayProtocol) ExtractIdentity(Conn net.Conn) (*RelayPeerContext, error) {
	packetConn, ok := Conn.(*quicConn)
	if !ok {
		return nil, fmt.Errorf("expect session connection to be quicConn")
	}
	if len(packetConn.Connection.ConnectionState().TLS.PeerCertificates) > 0 {
		return &RelayPeerContext{Name: packetConn.Connection.ConnectionState().TLS.PeerCertificates[0].Subject.CommonName}, nil
	}
	return nil, fmt.Errorf("no certificate found")
}

// CreateRelayQuicListener returns the listener that can be used for relay server serving.
func CreateRelayQuicListener(Addr string, TLSConfig *tls.Config, QuicConfig *quic.Config) (net.Listener, error) {
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
	if _, err := doClientHandshake(stream, &RelayRequest{Type: Bind, Payload: Channel}); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	return WithListener(&quicConnListener{conn}, []string{fmt.Sprintf("quicf://%s/%s", Addr, Channel)}), nil
}

func quicDialer(address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quicConn, error) {
	conn, err := quic.DialAddr(address, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	return &quicConn{Connection: conn, Stream: stream}, nil
}

func newClientQuicBasedSession(dialer func() (net.Conn, error), channel string) (Session, error) {
	qconn, err := dialer()
	if err != nil {
		return nil, err
	}
	var conn quic.Connection
	if quicConn, ok := qconn.(*quicConn); ok {
		conn = quicConn.Connection
	} else {
		return nil, fmt.Errorf("invalid dialer")
	}
	if _, err := doClientHandshake(qconn, &RelayRequest{Type: Dial, Payload: channel}); err != nil {
		qconn.Close()
		return nil, err
	}

	sessionInfo, err := getChannelInfo(dialer, channel)
	if err != nil {
		sessionInfo = nil
	}
	return &clientSession{
		done:     make(chan struct{}),
		isClosed: false,
		dialer: func() (net.Conn, error) {
			stream, err := conn.OpenStream()
			if err != nil {
				return nil, err
			}
			if _, err := doClientHandshake(stream, &RelayRequest{Type: Nop}); err != nil {
				stream.CancelRead(0)
				stream.Close()
				return nil, err
			}
			return createTrackConn(&quicConn{Stream: stream, Connection: conn}, "corenet_client_quic_active_connections"), nil
		},
		infoFn: func() (*SessionInfo, error) {
			if sessionInfo == nil {
				return nil, fmt.Errorf("not supported")
			}
			return sessionInfo, nil
		},
		closer:         func() error { return conn.CloseWithError(1, "") },
		isDialerClosed: func() bool { return conn.Context().Err() != nil },
	}, nil
}
