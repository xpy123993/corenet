package corenet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

type clientSession struct {
	dialer func() (net.Conn, error)

	mu       sync.RWMutex
	isClosed bool
	done     chan struct{}
}

// Session is an interface to provide multiplex connection and record its connection state.
type Session interface {
	Close() error
	Done() chan struct{}
	IsClosed() bool
	Dial() (net.Conn, error)
}

func (s *clientSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	close(s.done)
	return nil
}

func (s *clientSession) Done() chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.done
}

func (s *clientSession) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isClosed
}

func (s *clientSession) Dial() (net.Conn, error) {
	conn, err := s.dialer()
	if err != nil {
		s.Close()
	}
	return conn, err
}

func newSessionWithKeepCloseDetection(nopDialer, dialer func() (net.Conn, error)) (Session, error) {
	conn, err := nopDialer()
	if err != nil {
		return nil, err
	}
	if n, err := conn.Write([]byte{Nop}); err != nil || n != 1 {
		conn.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("cannot finish handshake")
	}
	session := clientSession{dialer: func() (net.Conn, error) {
		conn, err := dialer()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write([]byte{Dial}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, isClosed: false, done: make(chan struct{})}
	go func() {
		conn.Read(make([]byte, 1))
		conn.Close()
		session.Close()
	}()
	return &session, nil
}

func newTCPSession(address string) (Session, error) {
	dialer := func() (net.Conn, error) { return net.DialTimeout("tcp", address, 3*time.Second) }
	return newSessionWithKeepCloseDetection(dialer, dialer)
}

// Dialer provides a general client to communicate with MultiListener.
type Dialer struct {
	fallbackAddress      []string
	updateChannelAddress bool
	tlsConfig            *tls.Config

	mu               sync.RWMutex
	channelAddresses map[string][]string
	channelSessions  map[string]Session
}

// NewDialer returns a dialer.
func NewDialer(FallbackAddress []string, Options ...DialerOption) *Dialer {
	dialer := Dialer{
		fallbackAddress:      FallbackAddress,
		updateChannelAddress: true,

		channelAddresses: make(map[string][]string),
		channelSessions:  make(map[string]Session),
	}
	for _, option := range Options {
		option.applyTo(&dialer)
	}
	return &dialer
}

func (d *Dialer) createConnection(address string, channel string) (Session, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "tcp":
		return newTCPSession(uri.Host)
	case "ttf":
		return newClientFallbackSession(uri.Host, channel, d.tlsConfig)
	case "quicf":
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		TLSConfig.NextProtos = append(TLSConfig.NextProtos, "quicf")
		return newQuicClientSession(uri.Host, channel, &TLSConfig)
	}
	return nil, fmt.Errorf("unknown protocol: %s", address)
}

func (d *Dialer) establishChannel(Channel string) (Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	addresses := append(d.channelAddresses[Channel], d.fallbackAddress...)
	for _, address := range addresses {
		session, err := d.createConnection(address, Channel)
		if err == nil {
			d.channelSessions[Channel] = session
			return session, nil
		}
	}
	return nil, fmt.Errorf("%s is unavailable", Channel)
}

// Dial creates a connection to `channel`.
func (d *Dialer) Dial(Channel string) (net.Conn, error) {
	d.mu.RLock()
	session, exist := d.channelSessions[Channel]
	d.mu.RUnlock()
	if exist && !session.IsClosed() {
		return session.Dial()
	}
	session, err := d.establishChannel(Channel)
	if err != nil {
		return nil, err
	}
	return session.Dial()
}
