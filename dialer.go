package corenet

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

type clientSession struct {
	dialer         func() (net.Conn, error)
	infoFn         func() (*SessionInfo, error)
	addr           string
	isDialerClosed func() bool
	closer         func() error

	mu       sync.RWMutex
	isClosed bool
	done     chan struct{}
}

// Session is an interface to provide multiplex connection and record its connection state.
type Session interface {
	Close() error
	IsClosed() bool
	Done() chan struct{}

	OpenConnection() (net.Conn, error)
	Info() (*SessionInfo, error)

	ID() string
	SetID(string)
}

func (s *clientSession) unsafeClose() error {
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	if s.closer != nil {
		s.closer()
	}
	close(s.done)
	return nil
}

func (s *clientSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsafeClose()
}

func (s *clientSession) Done() chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.done
}

func (s *clientSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return true
	}
	if s.isDialerClosed != nil && s.isDialerClosed() {
		s.unsafeClose()
		s.isClosed = true
	}
	return s.isClosed
}

func (s *clientSession) OpenConnection() (net.Conn, error) {
	if s.IsClosed() {
		return nil, fmt.Errorf("already closed")
	}
	conn, err := s.dialer()
	if err != nil {
		s.Close()
	}
	return conn, err
}

func (s *clientSession) Info() (*SessionInfo, error) {
	if s.IsClosed() {
		return nil, fmt.Errorf("already closed")
	}
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
	session := clientSession{
		dialer: func() (net.Conn, error) {
			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return nil, err
			}
			if _, err := conn.Write([]byte{Dial}); err != nil {
				conn.Close()
				return nil, err
			}
			return createTrackConn(conn, "corenet_client_direct_tcp_active_connections"), nil
		},
		infoFn: func() (*SessionInfo, error) {
			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			sessionInfo, err := getSessionInfo(conn)
			if err != nil {
				return nil, err
			}
			return sessionInfo, nil
		},
		closer:   conn.Close,
		isClosed: false,
		done:     make(chan struct{}),
	}
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
	kcpConfig             *KCPConfig
	logError              bool

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

// createConnection is lock-free.
func (d *Dialer) createConnection(address string, channel string) (Session, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if len(uri.Port()) == 0 {
		uri.Host = uri.Host + ":13300"
	}
	switch uri.Scheme {
	case "tcp":
		return newClientTCPSession(uri.Host)
	case "ttf":
		return newClientListenerBasedSession(channel, func() (net.Conn, error) {
			return tls.Dial("tcp", uri.Host, d.tlsConfig)
		})
	case "ktf":
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		kcpConfig := d.kcpConfig
		if kcpConfig == nil {
			kcpConfig = DefaultKCPConfig()
		}
		TLSConfig.ServerName = uri.Hostname()
		return newClientKcpBasedSession(uri.Host, channel, &TLSConfig, kcpConfig)
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

// establishChannel is lock-free.
func (d *Dialer) establishChannel(Channel string, addresses []string, curSession Session) (Session, error) {
	for _, address := range addresses {
		addressURI, err := url.Parse(address)
		if err != nil {
			continue
		}
		if curSession != nil && !curSession.IsClosed() && curSession.ID() == addressURI.Hostname() {
			return curSession, nil
		}
		session, err := d.createConnection(address, Channel)
		if err == nil {
			session.SetID(addressURI.Hostname())
			return session, nil
		}
		if d.logError {
			log.Printf("Try dial to `%s` using address `%s`: %v", Channel, address, err)
		}
	}
	return nil, fmt.Errorf("%s is unavailable", Channel)
}

// unsafeGetChannelState requires locks.
func (d *Dialer) unsafeGetChannelState(Channel string) ([]string, Session) {
	addresses := []string{}
	addresses = append(addresses, d.channelAddresses[Channel]...)
	addresses = append(addresses, d.fallbackAddress...)
	return addresses, d.channelSessions[Channel]
}

// tryUpdateSession is thread-safe.
func (d *Dialer) tryUpdateSession(Channel string) (Session, error) {
	d.mu.RLock()
	addresses, curSession := d.unsafeGetChannelState(Channel)
	d.mu.RUnlock()
	session, err := d.establishChannel(Channel, addresses, curSession)
	if err != nil {
		return nil, err
	}
	sessionInfo, err := session.Info()
	if err != nil {
		sessionInfo = nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	originalSession, exist := d.channelSessions[Channel]
	if !exist || originalSession.IsClosed() || originalSession.ID() != session.ID() {
		if originalSession != nil {
			originalSession.Close()
			log.Printf("Upgrade connection to `%s`: `%s` -> `%s`", Channel, originalSession.ID(), session.ID())
		}
		d.channelAddresses[Channel] = sessionInfo.Addresses
		d.channelSessions[Channel] = session
		return session, nil
	}
	if session != originalSession {
		session.Close()
	}
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
				activeChannels := []string{}
				d.mu.RLock()
				for channel := range d.channelAddresses {
					activeChannels = append(activeChannels, channel)
				}
				d.mu.RUnlock()
				for _, channel := range activeChannels {
					d.tryUpdateSession(channel)
				}
			}
		}
	}()
}

// Dial creates a connection to `channel`.
func (d *Dialer) Dial(Channel string) (net.Conn, error) {
	d.mu.RLock()
	session, exists := d.channelSessions[Channel]
	d.mu.RUnlock()
	if exists && !session.IsClosed() {
		return session.OpenConnection()
	}
	if session == nil {
		d.tryUpdateSession(Channel)
	}
	session, err := d.tryUpdateSession(Channel)
	if err != nil {
		return nil, err
	}
	return session.OpenConnection()
}

// GetSessionID returns the session information of the channel.
func (d *Dialer) GetSessionID(Channel string) (string, error) {
	d.mu.RLock()
	addresses, session := d.unsafeGetChannelState(Channel)
	d.mu.RUnlock()
	if session != nil && !session.IsClosed() {
		return session.ID(), nil
	}
	session, err := d.establishChannel(Channel, addresses, session)
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
