package corenet

import (
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
)

type addr struct {
	str string
}

func (a *addr) Network() string { return "multi" }
func (a *addr) String() string  { return a.str }

type multiListener struct {
	done      chan struct{}
	connChan  chan net.Conn
	addresses []string
	listeners []net.Listener

	inflight sync.WaitGroup
	mu       sync.Mutex
	isClosed bool
}

// NewMultiListener returns a general listener that listens on all adapters.
// This listener returns streaming connection.
func NewMultiListener(adapters ...ListenerAdapter) net.Listener {
	l := &multiListener{
		done:      make(chan struct{}),
		connChan:  make(chan net.Conn),
		addresses: []string{},
		listeners: []net.Listener{},
		isClosed:  false,
	}

	for _, adapter := range adapters {
		adapter.applyTo(l)
	}
	for _, listener := range l.listeners {
		go func(listener net.Listener) {
			l.serveListener(listener)
			l.Close()
		}(listener)
	}
	return l
}

func (l *multiListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return nil
	}
	l.isClosed = true
	for _, listener := range l.listeners {
		listener.Close()
	}
	close(l.done)
	l.inflight.Wait()
	close(l.connChan)
	return nil
}

func (l *multiListener) IsClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.isClosed
}

func (l *multiListener) serveIncomingConn(conn net.Conn) {
	p := make([]byte, 1)
	if n, err := conn.Read(p); err != nil || n != 1 {
		conn.Close()
		return
	}

	switch p[0] {
	case Nop:
		conn.Read(p)
		conn.Close()
	case Info:
		json.NewEncoder(conn).Encode(SessionInfo{Addresses: l.addresses})
		conn.Close()
	case Dial:
		if l.IsClosed() {
			conn.Close()
			return
		}
		l.inflight.Add(1)
		defer l.inflight.Done()
		select {
		case <-l.done:
			conn.Close()
			return
		case l.connChan <- conn:
		}
	}

}

func (l *multiListener) serveListener(raw net.Listener) {
	globalStatsCounterMap.Inc("corenet_listener_active_listeners")
	defer globalStatsCounterMap.Dec("corenet_listener_active_listeners")

	defer l.Close()
	for {
		conn, err := raw.Accept()
		if err != nil {
			return
		}
		go l.serveIncomingConn(conn)
	}
}

func (l *multiListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
	case conn, ok := <-l.connChan:
		if ok {
			return createTrackConn(conn, "corenet_listener_active_connections"), nil
		}
	}
	return nil, io.EOF
}

func (l *multiListener) Addr() net.Addr {
	return &addr{
		str: strings.Join(l.addresses, ","),
	}
}
