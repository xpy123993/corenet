package corenet

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

type clientSession struct {
	dialer func() (net.Conn, error)
	infoFn func() (*SessionInfo, error)
	addr   string

	mu       sync.RWMutex
	isClosed bool
	done     chan struct{}
}

// Session is an interface to provide multiplex connection and record its connection state.
type Session interface {
	Close() error
	IsClosed() bool
	Done() chan struct{}

	Dial() (net.Conn, error)
	Info() (*SessionInfo, error)

	ID() string
	SetID(string)
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

func (s *clientSession) Info() (*SessionInfo, error) {
	if s.infoFn == nil {
		return nil, fmt.Errorf("info func unimplemented")
	}
	info, err := s.infoFn()
	if err != nil {
		s.Close()
	}
	return info, err
}

func (s *clientSession) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *clientSession) SetID(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = v
}

type clientTCPSession struct {
	conn    net.Conn
	address string

	id       string
	mu       sync.Mutex
	isClosed bool
	close    chan struct{}
}

func (s *clientTCPSession) Close() error {
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

func (s *clientTCPSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isClosed
}

func (s *clientTCPSession) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *clientTCPSession) SetID(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = v
}

func (s *clientTCPSession) Dial() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", s.address, 3*time.Second)
	if err != nil {
		s.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{Dial}); err != nil {
		s.Close()
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *clientTCPSession) Info() (*SessionInfo, error) {
	conn, err := net.DialTimeout("tcp", s.address, 3*time.Second)
	if err != nil {
		s.Close()
		return nil, err
	}
	defer conn.Close()
	sessionInfo, err := getSessionInfo(conn)
	if err != nil {
		s.Close()
		return nil, err
	}
	return sessionInfo, nil
}

func (s *clientTCPSession) Done() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.close
}

func newClientTCPSession(address string) (Session, error) {
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
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
	session := clientTCPSession{conn: conn, address: address, id: fmt.Sprintf("tcp://%s", address), close: make(chan struct{}), isClosed: false}
	go func() {
		conn.Read(make([]byte, 1))
		session.Close()
	}()
	return &session, nil
}

// Dialer provides a general client to communicate with MultiListener.
type Dialer struct {
	fallbackAddress       []string
	updateChannelAddress  bool
	updateChannelInterval time.Duration
	tlsConfig             *tls.Config
	quicConfig            *quic.Config

	mu               sync.RWMutex
	isClosed         bool
	close            chan struct{}
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

		isClosed:              false,
		close:                 make(chan struct{}),
		updateChannelInterval: 30 * time.Second,
	}
	for _, option := range Options {
		option.applyTo(&dialer)
	}
	if dialer.updateChannelAddress {
		dialer.spawnBackgroundRoutine()
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
		return newClientTCPSession(uri.Host)
	case "ttf":
		return newClientListenerBasedSession(uri.Host, channel, d.tlsConfig)
	case "quicf":
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		TLSConfig.NextProtos = append(TLSConfig.NextProtos, "quicf")
		return newClientQuicBasedSession(uri.Host, channel, &TLSConfig, d.quicConfig)
	}
	return nil, fmt.Errorf("unknown protocol: %s", address)
}

func (d *Dialer) establishChannel(Channel string) (Session, error) {
	addresses := make([]string, 0)
	d.mu.RLock()
	addresses = append(addresses, d.channelAddresses[Channel]...)
	addresses = append(addresses, d.fallbackAddress...)
	curSession := d.channelSessions[Channel]
	d.mu.RUnlock()
	for _, address := range addresses {
		if curSession != nil && !curSession.IsClosed() && curSession.ID() == address {
			return curSession, nil
		}
		session, err := d.createConnection(address, Channel)
		if err == nil {
			session.SetID(address)
			return session, nil
		}
	}
	return nil, fmt.Errorf("%s is unavailable", Channel)
}

func (d *Dialer) tryUpdateSession(Channel string) (Session, error) {
	session, err := d.establishChannel(Channel)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	originalSession, exist := d.channelSessions[Channel]
	if !exist || originalSession.ID() != session.ID() {
		if originalSession != nil {
			originalSession.Close()
		}
		d.channelSessions[Channel] = session
		log.Printf("Upgrade connection to `%s`: `%s` -> `%s`", Channel, originalSession.ID(), session.ID())
		return session, nil
	}
	session.Close()
	return originalSession, nil
}

func (d *Dialer) spawnBackgroundRoutine() {
	go func() {
		ticker := time.NewTicker(d.updateChannelInterval)
		defer ticker.Stop()
		for {
			select {
			case <-d.close:
				return
			case <-ticker.C:
				channelAddresses := make(map[string][]string)
				d.mu.RLock()
				for channel, address := range d.channelAddresses {
					channelAddresses[channel] = append(channelAddresses[channel], address...)
				}
				d.mu.RUnlock()
				for channel := range channelAddresses {
					d.tryUpdateSession(channel)
				}
			}
		}
	}()
}

// DialIgnoreSessionCache dials to `channel` ignoring the session cache.
func (d *Dialer) DialIgnoreSessionCache(Channel string) (net.Conn, error) {
	session, err := d.establishChannel(Channel)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.channelSessions[Channel] = session
	d.mu.Unlock()
	if d.updateChannelAddress {
		sessionInfo, err := session.Info()
		if err != nil {
			log.Printf("Cannot get session info: %v", err)
		} else {
			mayUpdate := false
			d.mu.Lock()
			if strings.Join(d.channelAddresses[Channel], ",") != strings.Join(sessionInfo.Addresses, ",") {
				d.channelAddresses[Channel] = sessionInfo.Addresses
				mayUpdate = true
			}
			d.mu.Unlock()
			if mayUpdate {
				return d.DialIgnoreSessionCache(Channel)
			}
		}
	}
	return session.Dial()
}

// Dial creates a connection to `channel`.
func (d *Dialer) Dial(Channel string) (net.Conn, error) {
	d.mu.RLock()
	session, exist := d.channelSessions[Channel]
	d.mu.RUnlock()
	if exist && !session.IsClosed() {
		return session.Dial()
	}
	return d.DialIgnoreSessionCache(Channel)
}

// GetSessionID returns the session information of the channel.
func (d *Dialer) GetSessionID(Channel string) (string, error) {
	d.mu.RLock()
	session, exist := d.channelSessions[Channel]
	d.mu.RUnlock()
	if exist && !session.IsClosed() {
		return session.ID(), nil
	}
	session, err := d.establishChannel(Channel)
	if err != nil {
		return "", err
	}
	return session.ID(), nil
}

// Close closes the dialer and all active sessions.
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isClosed {
		return nil
	}
	d.isClosed = true
	close(d.close)
	for _, session := range d.channelSessions {
		session.Close()
	}
	return nil
}
