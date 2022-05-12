package corenet

import (
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
}

func (s *clientSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	return nil
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
	n, err := conn.Write([]byte{Dial})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if n != 1 {
		conn.Close()
		return nil, fmt.Errorf("cannot finish handshake")
	}
	return conn, err
}

func newSession(dialer func() (net.Conn, error)) (*clientSession, error) {
	conn, err := dialer()
	if err != nil {
		return nil, err
	}
	n, err := conn.Write([]byte{Nop})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if n != 1 {
		conn.Close()
		return nil, fmt.Errorf("cannot finish handshake")
	}
	session := &clientSession{dialer: dialer}
	go func() {
		conn.Read(make([]byte, 1))
		conn.Close()
		session.Close()
	}()
	return session, nil
}

func newTCPSession(address string) (*clientSession, error) {
	return newSession(func() (net.Conn, error) {
		return net.DialTimeout("tcp", address, 3*time.Second)
	})
}

type Dialer struct {
	fallbackAddress      []string
	updateChannelAddress bool

	mu               sync.RWMutex
	channelAddresses map[string][]string
	channelSessions  map[string]*clientSession
}

func NewDialer(FallbackAddress []string, Options ...DialerOption) *Dialer {
	dialer := Dialer{
		fallbackAddress:      FallbackAddress,
		updateChannelAddress: true,

		channelAddresses: make(map[string][]string),
		channelSessions:  make(map[string]*clientSession),
	}
	for _, option := range Options {
		option.applyTo(&dialer)
	}
	return &dialer
}

func (d *Dialer) createConnection(address string) (*clientSession, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "tcp":
		return newTCPSession(uri.Host)
	}
	return nil, fmt.Errorf("unknown protocol: %s", address)
}

func (d *Dialer) establishChannel(Channel string) (*clientSession, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	addresses := append(d.channelAddresses[Channel], d.fallbackAddress...)
	for _, address := range addresses {
		session, err := d.createConnection(address)
		if err == nil {
			d.channelSessions[Channel] = session
			return session, nil
		}
	}
	return nil, fmt.Errorf("%s is unavailable", Channel)
}

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
