package corenet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"golang.org/x/net/trace"
)

// RelayPeerContext stores the peer identification.
type RelayPeerContext struct {
	Name string
}

// RelayProtocol specifies the relay protocol.
type RelayProtocol interface {
	// InitClientSession converts a client connection to a session.
	InitClientSession(ClientConn net.Conn) (Session, error)
	// InitChannelSession converts a listener connection to a session.
	InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error)
	// ExtractIdentity extracts the identity from the connection.
	ExtractIdentity(Conn net.Conn) (*RelayPeerContext, error)
	// ServeChannel is the channel where the relay server will redirect serve requests.
	// Optional, can return nil.
	ServeChannel() chan serveContext
}

// RelayServer redirects traffic between client and listener.
type RelayServer struct {
	mu         sync.RWMutex
	routeTable map[string]Session
	isClosed   bool
	close      chan struct{}

	logError                     bool
	forceEvictChannelSession     bool
	unsecureSkipPeerContextCheck bool
}

// RelayServerOption specifies a brdige server option.
type RelayServerOption interface {
	applyTo(*RelayServer)
}

type relayServerOptionApplier struct {
	applyFn func(*RelayServer)
}

func (a *relayServerOptionApplier) applyTo(s *RelayServer) { a.applyFn(s) }

// WithRelayServerLogError specifies if the relay server should log error status while serving.
// By default is false.
func WithRelayServerLogError(v bool) RelayServerOption {
	return &relayServerOptionApplier{
		applyFn: func(bs *RelayServer) {
			bs.logError = v
		},
	}
}

// WithRelayServerForceEvictChannelSession specifies whether the relay server should evict old channel session if there is a new one.
// By default is false, new channel session will be closed with channel already exists error.
func WithRelayServerForceEvictChannelSession(v bool) RelayServerOption {
	return &relayServerOptionApplier{
		applyFn: func(bs *RelayServer) {
			bs.forceEvictChannelSession = v
		},
	}
}

// WithRelayServerUnsecureSkipPeerContextCheck specifies whether to force check peer's certificate.
func WithRelayServerUnsecureSkipPeerContextCheck(v bool) RelayServerOption {
	return &relayServerOptionApplier{
		applyFn: func(bs *RelayServer) {
			bs.unsecureSkipPeerContextCheck = v
		},
	}
}

type serveContext struct {
	conn    net.Conn
	channel string
}

// NewRelayServer returns a relay server.
func NewRelayServer(Options ...RelayServerOption) *RelayServer {
	bs := &RelayServer{
		routeTable: make(map[string]Session),
		isClosed:   false,
		close:      make(chan struct{}),

		logError:                     false,
		forceEvictChannelSession:     false,
		unsecureSkipPeerContextCheck: false,
	}
	for _, option := range Options {
		option.applyTo(bs)
	}
	go bs.gcRoutine()
	return bs
}

func (s *RelayServer) lookupChannel(channel string) Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, exist := s.routeTable[channel]; exist && !session.IsClosed() {
		return session
	}
	return nil
}

func (s *RelayServer) registerChannel(channel string, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, exist := s.routeTable[channel]; exist {
		if !session.IsClosed() && !s.forceEvictChannelSession {
			return fmt.Errorf("channel `%s` is already registered", channel)
		}
		session.Close()
		delete(s.routeTable, channel)
	}
	s.routeTable[channel] = session
	return nil
}

func (s *RelayServer) serveBind(conn net.Conn, channel string, protocol RelayProtocol) error {
	tracker := trace.New("Relay.Bind", channel)
	defer tracker.Finish()

	if err := json.NewEncoder(conn).Encode(RelayResponse{Success: true}); err != nil {
		tracker.LazyPrintf("Post handshake error: %v", err)
		tracker.SetError()
		return err
	}

	session, err := protocol.InitChannelSession(channel, conn)
	if err != nil {
		tracker.LazyPrintf("Initialize channel error: %v", err)
		tracker.SetError()
		return err
	}

	if err := s.registerChannel(channel, session); err != nil {
		tracker.LazyPrintf("Register channel error: %v", err)
		tracker.SetError()
		session.Close()
		return err
	}

	<-session.Done()

	tracker.LazyPrintf("Session is closed")

	s.mu.Lock()
	defer s.mu.Unlock()
	if session == s.routeTable[channel] {
		delete(s.routeTable, channel)
		tracker.LazyPrintf("Session is removed from the channel table")
	}
	return nil
}

type countReader struct {
	io.Reader
	callback func(int64)
}

func (r *countReader) Read(buf []byte) (int, error) {
	n, err := r.Reader.Read(buf)
	if err == nil {
		r.callback(int64(n))
	}
	return n, err
}

func countCopy(reader io.Reader, writer io.Writer, callback func(int64)) (int64, error) {
	return io.Copy(writer, &countReader{Reader: reader, callback: callback})
}

func (s *RelayServer) serveDial(conn net.Conn, req *RelayRequest, protocol RelayProtocol) error {
	peerContext, err := protocol.ExtractIdentity(conn)
	if err != nil {
		if !s.unsecureSkipPeerContextCheck {
			json.NewEncoder(conn).Encode(RelayResponse{Success: false, Payload: "verification failed"})
			return err
		}
		peerContext = &RelayPeerContext{Name: "unknown"}
	}

	tracker := trace.New("Relay.Dial", req.Payload)
	defer tracker.Finish()

	channelSession := s.lookupChannel(req.Payload)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(RelayResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", req.Payload)})
		tracker.LazyPrintf("Channel not found.")
		tracker.SetError()
		return fmt.Errorf("channel `%s` not exists", req.Payload)
	}
	if err := json.NewEncoder(conn).Encode(RelayResponse{Success: true}); err != nil {
		tracker.LazyPrintf("Post handshake error: %v", err)
		tracker.SetError()
		return err
	}

	clientSession, err := protocol.InitClientSession(conn)
	if err != nil {
		tracker.LazyPrintf("Initialize client session error: %v", err)
		tracker.SetError()
		return err
	}
	defer clientSession.Close()

	clientContext, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	for {
		conn, err := clientSession.OpenConnection(false)
		if err != nil {
			tracker.LazyPrintf("Client session closed: %v", err)
			tracker.SetError()
			return err
		}
		channelConn, err := channelSession.OpenConnection(true)
		if err != nil {
			tracker.LazyPrintf("Channel session closed: %v", err)
			tracker.SetError()
			conn.Close()
			return err
		}
		trackEntry := globalStatsCounterMap.getEntry(fmt.Sprintf("corenet_relay_active_serving_connections{client=\"%s\", channel=\"%s\"}", peerContext.Name, req.Payload))
		go func(conn, channelConn net.Conn) {
			connTracker := trace.New("Relay.Serve", fmt.Sprintf("`%s` <=> `%s`", peerContext.Name, req.Payload))
			trackEntry.Inc()
			defer trackEntry.Dec()

			ctx, cancelFn := context.WithCancel(clientContext)
			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				connTracker.LazyPrintf("Write connection is opened")
				entry := globalStatsCounterMap.getEntry(fmt.Sprintf("corenet_relay_transfer_bytes{source=\"%s\", target=\"%s\"}", peerContext.Name, req.Payload))
				countCopy(channelConn, conn, func(i int64) {
					entry.Delta(i)
				})
				cancelFn()
				connTracker.LazyPrintf("Write connection is closed")
				wg.Done()
			}()
			go func() {
				connTracker.LazyPrintf("Read connection is opened")
				entry := globalStatsCounterMap.getEntry(fmt.Sprintf("corenet_relay_transfer_bytes{source=\"%s\", target=\"%s\"}", req.Payload, peerContext.Name))
				countCopy(conn, channelConn, func(i int64) {
					entry.Delta(i)
				})
				cancelFn()
				connTracker.LazyPrintf("Read connection is closed")
				wg.Done()
			}()
			<-ctx.Done()
			conn.Close()
			channelConn.Close()
			wg.Wait()
			connTracker.LazyPrintf("Connection closed: %v", ctx.Err())
			connTracker.Finish()
		}(conn, channelConn)
	}
}

func (s *RelayServer) serveInfo(conn net.Conn, channel string) error {
	tracker := trace.New("Relay.Info", channel)
	defer tracker.Finish()

	channelSession := s.lookupChannel(channel)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(RelayResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", channel)})
		tracker.LazyPrintf("Channel not found.")
		tracker.SetError()
		return fmt.Errorf("channel `%s` not exists", channel)
	}
	resp := RelayResponse{Success: true}
	sessionInfo, err := channelSession.Info()
	if err == nil {
		resp.SessionInfo = *sessionInfo
	}
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		tracker.LazyPrintf("Client session closed: %v", err)
		tracker.SetError()
		return err
	}
	return nil
}

func (s *RelayServer) serveConnection(conn net.Conn, protocol RelayProtocol) {
	closeConnectionAfterExit := true
	defer func() {
		if closeConnectionAfterExit {
			conn.Close()
		}
	}()
	req := RelayRequest{}
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	trackLabel := fmt.Sprintf("corenet_relay_active_raw_connections{method=\"%s\"}", GetCommandName(req.Type))
	globalStatsCounterMap.Inc(trackLabel)
	defer globalStatsCounterMap.Dec(trackLabel)

	var result error
	switch req.Type {
	case Bind:
		result = s.serveBind(conn, req.Payload, protocol)
	case Dial:
		result = s.serveDial(conn, &req, protocol)
	case Info:
		result = s.serveInfo(conn, req.Payload)
	case Serve:
		if protocol.ServeChannel() != nil {
			protocol.ServeChannel() <- serveContext{conn: conn, channel: req.Payload}
			closeConnectionAfterExit = false
		}
	case Nop:
		conn.Read(make([]byte, 1))
	}
	if s.logError && result != nil {
		log.Printf("Connection closed with error: %v", result)
	}
}

// Serve starts the relay service on the specified listener.
func (s *RelayServer) Serve(listener net.Listener, protocol RelayProtocol) error {
	go func() {
		<-s.close
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(conn, protocol)
	}
}

func (s *RelayServer) ServeURL(address string, tlsConfig *tls.Config) error {
	serverURL, err := url.Parse(address)
	if err != nil {
		return err
	}
	port := serverURL.Port()
	if len(port) == 0 {
		port = "13300"
	}
	serviceAddress := fmt.Sprintf(":%s", port)
	switch serverURL.Scheme {
	case "ttf":
		lis, err := (&net.ListenConfig{
			KeepAlive: 10 * time.Second,
		}).Listen(context.Background(), "tcp", serviceAddress)
		if err != nil {
			return fmt.Errorf("failed to bind %s: %v", serverURL.String(), err)
		}
		return s.Serve(tls.NewListener(lis, tlsConfig), UseSmuxRelayProtocol())
	case "ktf":
		relayServerListener, err := CreateRelayKCPListener(serviceAddress, tlsConfig, DefaultKCPConfig())
		if err != nil {
			return fmt.Errorf("failed to bind %s: %v", serverURL.String(), err)
		}
		return s.Serve(relayServerListener, UseSmuxRelayProtocol())
	case "quicf":
		relayServerListener, err := CreateRelayQuicListener(serviceAddress, tlsConfig, &quic.Config{})
		if err != nil {
			return fmt.Errorf("failed to bind %s: %v", serverURL.String(), err)
		}
		return s.Serve(relayServerListener, UseQuicRelayProtocol())
	}
	return fmt.Errorf("unsupported scheme: %s", serverURL.Scheme)
}

func (s *RelayServer) gcRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.close:
			return
		case <-ticker.C:
			s.mu.RLock()
			for _, session := range s.routeTable {
				if session.IsClosed() {
					session.Close()
				}
			}
			s.mu.RUnlock()
		}
	}
}

// Close closes a relay server.
func (s *RelayServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	close(s.close)
	return nil
}

func doClientHandshake(conn io.ReadWriter, req *RelayRequest) (*RelayResponse, error) {
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("remote error: %v", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Payload)
	}
	return &resp, nil
}

func extractIdentityFromTLSConn(conn net.Conn) (*RelayPeerContext, error) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
			return &RelayPeerContext{Name: tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName}, nil
		}
		return nil, fmt.Errorf("no certificate found from the tls connection")
	}
	return nil, fmt.Errorf("not supported")
}
