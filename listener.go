package corenet

import (
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	Nop = iota
	Dial
	Info
)

type listenerInfo struct {
	Addresses []string `json:"addresses"`
}

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

	mu       sync.Mutex
	isClosed bool
}

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
		go l.serveListener(listener)
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
		json.NewEncoder(conn).Encode(listenerInfo{Addresses: l.addresses})
		conn.Close()
	case Dial:
		select {
		case <-l.done:
			conn.Close()
			return
		case l.connChan <- conn:
		}
	}

}

func (l *multiListener) serveListener(raw net.Listener) {
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
			return conn, nil
		}
	}
	return nil, io.EOF
}

func (l *multiListener) Addr() net.Addr {
	return &addr{
		str: strings.Join(l.addresses, ","),
	}
}
