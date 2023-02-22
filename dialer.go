package corenet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
)

var (
	sessionOpenTimeout = 5 * time.Second
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

	OpenConnection(withTimeout bool) (net.Conn, error)
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

func (s *clientSession) OpenConnection(withTimeout bool) (net.Conn, error) {
	if s.IsClosed() {
		return nil, fmt.Errorf("already closed")
	}
	if withTimeout {
		t := globalStatsCounterMap.getEntry(fmt.Sprintf("corenet_session_pending_connections{session=\"%s\"}", s.ID()))
		t.Inc()
		handshakeFinished := make(chan struct{})
		defer func() {
			close(handshakeFinished)
			t.Dec()
		}()
		go func() {
			timer := time.NewTimer(sessionOpenTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				s.Close()
			case <-handshakeFinished:
			}
		}()
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
	return s.infoFn()
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

func parseSessionID(URI string) (string, error) {
	sessionURL, err := url.Parse(URI)
	if err != nil {
		return "", err
	}
	sessionURL.RawQuery = ""
	return sessionURL.String(), nil
}

func newClientDirectSession(dialer func() (net.Conn, error)) (Session, error) {
	conn, err := dialer()
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
	trackerConns := make([]net.Conn, 0)
	session := clientSession{
		dialer: func() (net.Conn, error) {
			conn, err := dialer()
			if err != nil {
				return nil, err
			}
			if _, err := conn.Write([]byte{Dial}); err != nil {
				conn.Close()
				return nil, err
			}
			clientConn := createTrackConn(conn, "corenet_client_direct_tcp_active_connections")
			trackerConns = append(trackerConns, clientConn)
			return clientConn, nil
		},
		infoFn: func() (*SessionInfo, error) {
			conn, err := dialer()
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			defer conn.Close()
			sessionInfo, err := getSessionInfo(conn)
			if err != nil {
				return nil, err
			}
			return sessionInfo, nil
		},
		closer: func() error {
			for _, sessionConn := range trackerConns {
				if sessionConn != nil {
					sessionConn.Close()
				}
			}
			return conn.Close()
		},
		isClosed: false,
		done:     make(chan struct{}),
	}
	go func() {
		conn.Read(make([]byte, 1))
		session.Close()
	}()
	return &session, nil
}

type dialerSession struct {
	dialer            func(address, channel string) (Session, error)
	channelName       string
	allowUpgrade      bool
	fallbackAddresses []string
	logError          bool

	mu               sync.Mutex
	channelAddresses []string
	session          Session
}

func newDialerSession(ChannelName string, InitialAddresses, FallbackAddresses []string, AllowUpgrade bool, LogError bool, Dialer func(address, channel string) (Session, error)) *dialerSession {
	s := &dialerSession{
		dialer:            Dialer,
		channelName:       ChannelName,
		allowUpgrade:      AllowUpgrade,
		fallbackAddresses: FallbackAddresses,
		channelAddresses:  InitialAddresses,
		logError:          LogError,
		session:           nil,
	}
	if s.channelAddresses == nil {
		s.channelAddresses = make([]string, 0)
	}
	if s.fallbackAddresses == nil {
		s.fallbackAddresses = make([]string, 0)
	}
	return s
}

func (d *dialerSession) unsafeUpgradeConnection() {
	addresses := append(d.channelAddresses, d.fallbackAddresses...)
	triedAddresses := make(map[string]bool)
	if d.session != nil && d.session.IsClosed() {
		d.session = nil
	}
	for _, address := range addresses {
		sessionID, err := parseSessionID(address)
		if err != nil {
			continue
		}
		if d.session != nil && !d.session.IsClosed() && d.session.ID() == sessionID {
			break
		}
		if tried, ok := triedAddresses[sessionID]; tried && ok {
			continue
		}
		triedAddresses[sessionID] = true
		newSession, err := d.dialer(address, d.channelName)
		if err == nil {
			if d.session != nil {
				d.session.Close()
			}
			d.session = newSession
			d.session.SetID(sessionID)
			if d.allowUpgrade {
				info, err := d.session.Info()
				needUpdate := false
				if err == nil {
					needUpdate = strings.Join(d.channelAddresses, ",") != strings.Join(info.Addresses, ",")
					d.channelAddresses = info.Addresses
				} else if !strings.HasPrefix(address, "udp://") && !strings.HasPrefix(address, "udf://") {
					// If the connection is not lossy, an info update failure will close the session.
					if d.logError {
						log.Printf("Failed to obtain connection info for %s: %v", address, err)
					}
					// If info contains error, this session is unlikely to be safe.
					d.session.Close()
					d.session = nil
					continue
				}
				if needUpdate {
					d.unsafeUpgradeConnection()
				}
			}
			return
		}
		if d.logError {
			log.Printf("Failed to create connection for %s: %v", address, err)
		}
	}
}

func (d *dialerSession) ID() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.session == nil || d.session.IsClosed() {
		return "", fmt.Errorf("unreachable")
	}
	return d.session.ID(), nil
}

func (d *dialerSession) Dial() (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.session == nil || d.session.IsClosed() {
		d.unsafeUpgradeConnection()
	}
	if d.session != nil {
		return d.session.OpenConnection(true)
	}
	return nil, fmt.Errorf("unavailable on all addresses")
}

func (d *dialerSession) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.session == nil {
		return nil
	}
	return d.session.Close()
}

func (d *dialerSession) UpgradeConnection() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.unsafeUpgradeConnection()
}

// Dialer provides a general client to communicate with MultiListener.
type Dialer struct {
	fallbackAddress            []string
	updateChannelAddress       bool
	updateChannelInterval      time.Duration
	tlsConfig                  *tls.Config
	quicConfig                 *quic.Config
	kcpConfig                  *KCPConfig
	logError                   bool
	channelCIDRblocklist       []netip.Prefix
	connectionAddressBlocklist map[string]bool
	channelAddresses           map[string][]string

	mu              sync.Mutex
	channelSessions map[string]*dialerSession
	isClosed        bool
	close           chan struct{}
}

// NewDialer returns a dialer.
func NewDialer(FallbackAddress []string, Options ...DialerOption) *Dialer {
	dialer := Dialer{
		fallbackAddress:      FallbackAddress,
		updateChannelAddress: true,

		channelCIDRblocklist:       make([]netip.Prefix, 0),
		connectionAddressBlocklist: make(map[string]bool),
		channelAddresses:           make(map[string][]string),

		channelSessions:       make(map[string]*dialerSession),
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

func (d *Dialer) getRelayDialer(uri *url.URL) (func() (net.Conn, error), error) {
	if len(uri.Port()) == 0 {
		uri.Host = uri.Host + ":13300"
	}
	switch uri.Scheme {
	case "ttf":
		return func() (net.Conn, error) {
			return tls.Dial("tcp", uri.Host, d.tlsConfig)
		}, nil
	case "ktf":
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		kcpConfig := d.kcpConfig
		if kcpConfig == nil {
			kcpConfig = DefaultKCPConfig()
		}
		if len(TLSConfig.ServerName) == 0 {
			TLSConfig.ServerName = uri.Hostname()
		}
		return func() (net.Conn, error) {
			return createKCPConnection(uri.Host, &TLSConfig, kcpConfig)
		}, nil
	case "udf":
		udpAddr, err := net.ResolveUDPAddr("udp", uri.Host)
		if err != nil {
			return nil, err
		}
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		if len(TLSConfig.ServerName) == 0 {
			TLSConfig.ServerName = uri.Hostname()
		}
		dtlsConfig := convertToDTLSConfig(&TLSConfig)
		dtlsConfig.ConnectContextMaker = func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 5*time.Second)
		}
		return func() (net.Conn, error) {
			raw, err := dtls.Dial("udp", udpAddr, dtlsConfig)
			if err != nil {
				return nil, err
			}
			return newBufferedConn(raw), nil
		}, nil
	case "quicf":
		var TLSConfig tls.Config
		if d.tlsConfig != nil {
			TLSConfig = *d.tlsConfig
		}
		TLSConfig.NextProtos = append(TLSConfig.NextProtos, "quicf")
		return func() (net.Conn, error) {
			return quicDialer(uri.Host, &TLSConfig, d.quicConfig)
		}, nil
	}
	return nil, fmt.Errorf("unknown protocol: %s", uri.String())
}

// createConnection has no lock inside.
func (d *Dialer) createConnection(address string, channel string) (Session, error) {
	sessionID, err := parseSessionID(address)
	if err != nil {
		return nil, errors.WithMessagef(err, "cannot parse listener address: %s", address)
	}
	if blocked, exists := d.connectionAddressBlocklist[sessionID]; exists && blocked {
		return nil, fmt.Errorf("address is in direct access blocklist")
	}
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	ipaddr, err := netip.ParseAddr(uri.Hostname())
	if err == nil {
		for _, net := range d.channelCIDRblocklist {
			if net.Contains(ipaddr) {
				return nil, fmt.Errorf("address is in direct access blocklist")
			}
		}
	}
	switch uri.Scheme {
	case "tcp", "udp":
		return newClientDirectSession(func() (net.Conn, error) {
			conn, err := net.DialTimeout(uri.Scheme, uri.Host, 3*time.Second)
			if err == nil && len(uri.Query().Get("key")) > 0 {
				if uri.Scheme == "udp" {
					conn.Close()
					return nil, fmt.Errorf("AES on unreliable protocol is not implemented")
				}
				dec, err := base64.RawURLEncoding.DecodeString(uri.Query().Get("key"))
				if err != nil {
					conn.Close()
					return nil, err
				}
				return newCryptoConn(conn, dec)
			}
			return conn, err
		})
	case "ttf", "ktf", "udf":
		dialer, err := d.getRelayDialer(uri)
		if err != nil {
			return nil, err
		}
		return newSmuxClientSession(dialer, channel)
	case "quicf":
		dialer, err := d.getRelayDialer(uri)
		if err != nil {
			return nil, err
		}
		return newClientQuicBasedSession(dialer, channel)
	}
	return nil, fmt.Errorf("unknown protocol: %s", address)
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
				d.mu.Lock()
				for _, channel := range d.channelSessions {
					go channel.UpgradeConnection()
				}
				d.mu.Unlock()
			}
		}
	}()
}

// Dial creates a connection to `channel`.
func (d *Dialer) Dial(Channel string) (net.Conn, error) {
	d.mu.Lock()
	session, exists := d.channelSessions[Channel]
	if !exists {
		session = newDialerSession(Channel, d.channelAddresses[Channel], d.fallbackAddress,
			d.updateChannelAddress, d.logError, d.createConnection)
		d.channelSessions[Channel] = session
	}
	d.mu.Unlock()
	return session.Dial()
}

// GetSessionID returns the session information of the channel.
func (d *Dialer) GetSessionID(Channel string) (string, error) {
	d.mu.Lock()
	session, exists := d.channelSessions[Channel]
	if !exists {
		d.mu.Unlock()
		return "", fmt.Errorf("unreachable")
	}
	d.mu.Unlock()
	return session.ID()
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

// Returns all channel infos from the relay server registered in this dialer as fallback addresses.
func (d *Dialer) GetChannelInfosFromRelay() ([]SessionInfo, error) {
	d.mu.Lock()
	relayAddresses := d.fallbackAddress
	d.mu.Unlock()
	sessionInfos := []SessionInfo{}
	for _, relayAddress := range relayAddresses {
		relayURL, err := url.Parse(relayAddress)
		if err != nil {
			continue
		}
		dialer, err := d.getRelayDialer(relayURL)
		if err != nil {
			continue
		}
		conn, err := dialer()
		if err != nil {
			continue
		}
		resp, err := doClientHandshake(conn, &RelayRequest{Type: Info, Payload: ""})
		if err != nil {
			log.Printf("Warning: cannot fetch infos from %s: %v", relayAddress, err)
			conn.Close()
			continue
		}
		conn.Close()
		sessionInfos = append(sessionInfos, resp.SessionInfo...)
	}
	return sessionInfos, nil
}
