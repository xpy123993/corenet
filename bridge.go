package corenet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// RelayProtocol specifies the relay protocol.
type RelayProtocol interface {
	// InitClientSession converts a client connection to a session.
	InitClientSession(ClientConn net.Conn) (Session, error)
	// InitChannelSession converts a listener connection to a session.
	InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error)
	// ServeChannel is the channel where the relay server will redirect serve requests.
	// Optional, can return nil.
	ServeChannel() chan serveContext
}

// RelayServer redirects traffic between client and listener.
type RelayServer struct {
	mu         sync.RWMutex
	routeTable map[string]Session

	logError                 bool
	forceEvictChannelSession bool
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

type serveContext struct {
	conn    net.Conn
	channel string
}

// NewRelayServer returns a relay server.
func NewRelayServer(Options ...RelayServerOption) *RelayServer {
	bs := &RelayServer{
		routeTable: make(map[string]Session),

		logError:                 false,
		forceEvictChannelSession: false,
	}
	for _, option := range Options {
		option.applyTo(bs)
	}
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
	if err := json.NewEncoder(conn).Encode(RelayResponse{Success: true}); err != nil {
		return err
	}

	session, err := protocol.InitChannelSession(channel, conn)
	if err != nil {
		return err
	}

	if err := s.registerChannel(channel, session); err != nil {
		session.Close()
		return err
	}

	globalStatsCounterMap.Inc("relay_active_channel")
	defer globalStatsCounterMap.Dec("relay_active_channel")

	<-session.Done()

	s.mu.Lock()
	defer s.mu.Unlock()
	if session == s.routeTable[channel] {
		delete(s.routeTable, channel)
	}
	return nil
}

func (s *RelayServer) serveDial(conn net.Conn, req *RelayRequest, protocol RelayProtocol) error {
	globalStatsCounterMap.Inc("relay_active_dialer")
	defer globalStatsCounterMap.Dec("relay_active_dialer")

	channelSession := s.lookupChannel(req.Payload)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(RelayResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", req.Payload)})
		return fmt.Errorf("channel `%s` not exists", req.Payload)
	}
	if err := json.NewEncoder(conn).Encode(RelayResponse{Success: true}); err != nil {
		return err
	}
	clientSession, err := protocol.InitClientSession(conn)
	if err != nil {
		return err
	}
	defer clientSession.Close()

	clientContext, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	for {
		conn, err := clientSession.OpenConnection()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			channelConn, err := channelSession.OpenConnection()
			if err != nil {
				return
			}
			defer channelConn.Close()

			globalStatsCounterMap.Inc("relay_active_connection")
			defer globalStatsCounterMap.Dec("relay_active_connection")

			ctx, cancelFn := context.WithCancel(clientContext)
			go func() { io.Copy(channelConn, conn); cancelFn() }()
			go func() { io.Copy(conn, channelConn); cancelFn() }()
			<-ctx.Done()
		}(conn)
	}
}

func (s *RelayServer) serveInfo(conn net.Conn, channel string) error {
	channelSession := s.lookupChannel(channel)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(RelayResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", channel)})
		return fmt.Errorf("channel `%s` not exists", channel)
	}
	resp := RelayResponse{Success: true}
	sessionInfo, err := channelSession.Info()
	if err == nil {
		resp.SessionInfo = *sessionInfo
	}
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
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
	globalStatsCounterMap.Inc(fmt.Sprintf("relay_%s", GetCommandName(req.Type)))
	defer globalStatsCounterMap.Dec(fmt.Sprintf("relay_%s", GetCommandName(req.Type)))

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
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(conn, protocol)
	}
}

func doClientHandshake(conn io.ReadWriter, req *RelayRequest) (*RelayResponse, error) {
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	resp := RelayResponse{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("remote error: %v", err)
	}
	return &resp, nil
}
