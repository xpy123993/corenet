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

// BridgeProtocol specifies the bridge protocol.
type BridgeProtocol interface {
	// InitClientSession converts a client connection to a session.
	InitClientSession(ClientConn net.Conn) (Session, error)
	// InitChannelSession converts a listener connection to a session.
	InitChannelSession(Channel string, ListenerConn net.Conn) (Session, error)
	// ServeChannel is the channel where the bridge server will redirect serve requests.
	// Optional, can return nil.
	ServeChannel() chan serveContext
}

// BridgeServer redirects traffic between client and listener.
type BridgeServer struct {
	mu         sync.RWMutex
	routeTable map[string]Session

	logError                 bool
	forceEvictChannelSession bool
}

// BridgeServerOption specifies a brdige server option.
type BridgeServerOption interface {
	applyTo(*BridgeServer)
}

type bridgeServerOptionApplier struct {
	applyFn func(*BridgeServer)
}

func (a *bridgeServerOptionApplier) applyTo(s *BridgeServer) { a.applyFn(s) }

// WithBridgeServerLogError specifies if the bridge server should log error status while serving.
// By default is false.
func WithBridgeServerLogError(v bool) BridgeServerOption {
	return &bridgeServerOptionApplier{
		applyFn: func(bs *BridgeServer) {
			bs.logError = v
		},
	}
}

// WithBridgeServerForceEvictChannelSession specifies whether the bridge server should evict old channel session if there is a new one.
// By default is false, new channel session will be closed with channel already exists error.
func WithBridgeServerForceEvictChannelSession(v bool) BridgeServerOption {
	return &bridgeServerOptionApplier{
		applyFn: func(bs *BridgeServer) {
			bs.forceEvictChannelSession = v
		},
	}
}

type serveContext struct {
	conn    net.Conn
	channel string
}

// NewBridgeServer returns a bridge server.
func NewBridgeServer(Options ...BridgeServerOption) *BridgeServer {
	bs := &BridgeServer{
		routeTable: make(map[string]Session),

		logError:                 false,
		forceEvictChannelSession: false,
	}
	for _, option := range Options {
		option.applyTo(bs)
	}
	return bs
}

func (s *BridgeServer) lookupChannel(channel string) Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, exist := s.routeTable[channel]; exist && !session.IsClosed() {
		return session
	}
	return nil
}

func (s *BridgeServer) registerChannel(channel string, session Session) error {
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

func (s *BridgeServer) serveBind(conn net.Conn, channel string, protocol BridgeProtocol) error {
	if err := json.NewEncoder(conn).Encode(BridgeResponse{Success: true}); err != nil {
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

	globalStatsCounterMap.Inc("bridge_active_channel")
	defer globalStatsCounterMap.Dec("bridge_active_channel")

	<-session.Done()

	s.mu.Lock()
	defer s.mu.Unlock()
	if session == s.routeTable[channel] {
		delete(s.routeTable, channel)
	}
	return nil
}

func (s *BridgeServer) serveDial(conn net.Conn, req *BridgeRequest, protocol BridgeProtocol) error {
	globalStatsCounterMap.Inc("bridge_active_dialer")
	defer globalStatsCounterMap.Dec("bridge_active_dialer")

	channelSession := s.lookupChannel(req.Payload)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(BridgeResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", req.Payload)})
		return fmt.Errorf("channel `%s` not exists", req.Payload)
	}
	if err := json.NewEncoder(conn).Encode(BridgeResponse{Success: true}); err != nil {
		return err
	}
	clientSession, err := protocol.InitClientSession(conn)
	if err != nil {
		return err
	}
	wg := sync.WaitGroup{}
	for !clientSession.IsClosed() {
		conn, err := clientSession.Dial()
		if err != nil {
			break
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer conn.Close()
			channelConn, err := channelSession.Dial()
			if err != nil {
				return
			}
			defer channelConn.Close()
			globalStatsCounterMap.Inc("bridge_active_connection")
			defer globalStatsCounterMap.Dec("bridge_active_connection")
			ctx, cancelFn := context.WithCancel(context.Background())
			go func() { io.Copy(channelConn, conn); cancelFn() }()
			go func() { io.Copy(conn, channelConn); cancelFn() }()
			<-ctx.Done()
		}(conn)
	}
	wg.Wait()
	return nil
}

func (s *BridgeServer) serveInfo(conn net.Conn, channel string) error {
	channelSession := s.lookupChannel(channel)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(BridgeResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", channel)})
		return fmt.Errorf("channel `%s` not exists", channel)
	}
	resp := BridgeResponse{Success: true}
	sessionInfo, err := channelSession.Info()
	if err == nil {
		resp.SessionInfo = *sessionInfo
	}
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		return err
	}
	return nil
}

func (s *BridgeServer) serveConnection(conn net.Conn, protocol BridgeProtocol) {
	globalStatsCounterMap.Inc("bridge_active_connection")
	defer globalStatsCounterMap.Dec("bridge_active_connection")

	closeConnectionAfterExit := true
	defer func() {
		if closeConnectionAfterExit {
			conn.Close()
		}
	}()
	req := BridgeRequest{}
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
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

// Serve starts the bridge service on the specified listener.
func (s *BridgeServer) Serve(listener net.Listener, protocol BridgeProtocol) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(conn, protocol)
	}
}
