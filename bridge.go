package corenet

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
)

// BridgeProtocol specifies the bridge protocol.
type BridgeProtocol interface {
	// InitSession converts a listener connection to a session.
	InitSession(Channel string, ListenerConn net.Conn) (Session, error)
	// BridgeSession serves builds connections between a client connection and a listener session.
	BridgeSession(Channel string, ClientConn net.Conn, ListenerSession Session) error
}

// BridgeServer redirects traffic between client and listener.
type BridgeServer struct {
	mu         sync.RWMutex
	routeTable map[string]Session

	sessionProtocol BridgeProtocol
	sessionAddress  string

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

// NewBridgeServer returns a bridge server. `SessionAddress` will be sent to the channel listener.
func NewBridgeServer(SessionProtocol BridgeProtocol, SessionAddress string, Options ...BridgeServerOption) *BridgeServer {
	bs := &BridgeServer{
		routeTable:      make(map[string]Session),
		sessionProtocol: SessionProtocol,
		sessionAddress:  SessionAddress,

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

func (s *BridgeServer) serveBind(conn net.Conn, channel string) error {
	if err := json.NewEncoder(conn).Encode(BridgeResponse{Success: true, Payload: s.sessionAddress}); err != nil {
		return err
	}

	session, err := s.sessionProtocol.InitSession(channel, conn)
	if err != nil {
		return err
	}

	if err := s.registerChannel(channel, session); err != nil {
		session.Close()
		return err
	}

	<-session.Done()

	s.mu.Lock()
	defer s.mu.Unlock()
	if session == s.routeTable[channel] {
		delete(s.routeTable, channel)
	}
	return nil
}

func (s *BridgeServer) serveDial(conn net.Conn, req *BridgeRequest) error {
	channelSession := s.lookupChannel(req.Payload)
	if channelSession == nil {
		json.NewEncoder(conn).Encode(BridgeResponse{Success: false, Payload: fmt.Sprintf("channel `%s` not exists", req.Payload)})
		return fmt.Errorf("channel `%s` not exists", req.Payload)
	}
	if err := json.NewEncoder(conn).Encode(BridgeResponse{Success: true}); err != nil {
		return err
	}
	return s.sessionProtocol.BridgeSession(req.Payload, conn, channelSession)
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

func (s *BridgeServer) serveConnection(conn net.Conn) {
	defer conn.Close()
	req := BridgeRequest{}
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	var result error
	switch req.Type {
	case Bind:
		result = s.serveBind(conn, req.Payload)
	case Dial:
		result = s.serveDial(conn, &req)
	case Info:
		result = s.serveInfo(conn, req.Payload)
	case Nop:
		conn.Read(make([]byte, 1))
	}
	if s.logError && result != nil {
		log.Printf("Connection closed with error: %v", result)
	}

}

// Serve starts the bridge service on the specified listener.
func (s *BridgeServer) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(conn)
	}
}