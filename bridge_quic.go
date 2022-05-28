package corenet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"

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

// UseQuicRelayProtocol provides a relay protocol based on quic.
func UseQuicRelayProtocol() RelayProtocol {
	return &quicRelayProtocol{}
}

type quicRelayProtocol struct {
}

func (p *quicRelayProtocol) ServeChannel() chan serveContext { return nil }

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
			return &quicConn{Stream: stream, Connection: packetConn.Connection}, nil
		},
	}
	go func() {
		select {
		case <-session.done:
		case <-packetConn.Context().Done():
			session.Close()
		}
		packetConn.Connection.CloseWithError(1, "")
	}()
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
			return &quicConn{Stream: stream, Connection: packetConn.Connection}, nil
		},
	}
	go func() {
		select {
		case <-session.done:
		case <-packetConn.Context().Done():
			session.Close()
		}
		packetConn.Connection.CloseWithError(1, "")
	}()
	return session, nil
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
	if err := json.NewEncoder(stream).Encode(RelayRequest{Type: Bind, Payload: Channel}); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	if !resp.Success {
		conn.CloseWithError(0, "")
		return nil, fmt.Errorf("remote error: %v", resp.Payload)
	}
	return WithListener(&quicConnListener{conn}, []string{fmt.Sprintf("quicf://%s?channel=%s", Addr, Channel)}), nil
}

type clientQuicSession struct {
	conn quic.Connection

	id       string
	mu       sync.Mutex
	isClosed bool
	close    chan struct{}
}

func (s *clientQuicSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.conn.CloseWithError(0, "")
	s.isClosed = true
	close(s.close)
	return nil
}

func (s *clientQuicSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return true
	}
	if s.conn.Context().Err() != nil {
		s.isClosed = true
	}
	return s.isClosed
}

func (s *clientQuicSession) Done() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.close
}

func (s *clientQuicSession) Dial() (net.Conn, error) {
	stream, err := s.conn.OpenStream()
	if err != nil {
		s.Close()
		return nil, err
	}
	if _, err := stream.Write([]byte{Dial}); err != nil {
		stream.CancelRead(1)
		stream.Close()
		s.Close()
		return nil, err
	}
	return createTrackConn(&quicConn{Stream: stream, Connection: s.conn}, "client_quic_active_connections"), nil
}

func (s *clientQuicSession) Info() (*SessionInfo, error) {
	stream, err := s.conn.OpenStream()
	if err != nil {
		s.Close()
		return nil, err
	}
	defer func() {
		stream.CancelRead(1)
		stream.Close()
	}()
	sessionInfo, err := getSessionInfo(stream)
	if err != nil {
		s.Close()
		return nil, err
	}
	return sessionInfo, nil
}

func (s *clientQuicSession) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *clientQuicSession) SetID(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = v
}

func newClientQuicBasedSession(address, channel string, tlsConfig *tls.Config, quicConfig *quic.Config) (Session, error) {
	conn, err := quic.DialAddr(address, tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}

	if err := json.NewEncoder(stream).Encode(&RelayRequest{Type: Dial, Payload: channel}); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}

	resp := RelayResponse{}
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		conn.CloseWithError(1, err.Error())
		return nil, err
	}
	if !resp.Success {
		conn.CloseWithError(1, resp.Payload)
		return nil, fmt.Errorf(resp.Payload)
	}

	session := &clientQuicSession{conn: conn, close: make(chan struct{}), isClosed: false}
	go func() {
		<-conn.Context().Done()
		session.Close()
	}()

	return session, nil
}
