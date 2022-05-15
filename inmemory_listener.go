package corenet

import (
	"io"
	"net"
	"sync"
)

// InmemoryListener implements a listener for testing purpose.
type InmemoryListener struct {
	done     chan struct{}
	connChan chan net.Conn

	mu       sync.RWMutex
	isClosed bool
}

// NewInMemoryListener creates an inmemory listener.
func NewInMemoryListener() *InmemoryListener {
	return &InmemoryListener{
		done:     make(chan struct{}),
		connChan: make(chan net.Conn),
		isClosed: false,
	}
}

// IsClosed returns if the listener is closed.
func (l *InmemoryListener) IsClosed() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.isClosed
}

// Close closes the listener. Will immeidately return nil if the listener is already closed.
func (l *InmemoryListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return nil
	}
	l.isClosed = true
	close(l.done)
	close(l.connChan)
	return nil
}

// Accept returns a connection just like net.Listener.
func (l *InmemoryListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
	case conn, ok := <-l.connChan:
		if ok {
			return conn, nil
		}
	}
	return nil, io.EOF
}

// Dial creates a connection to the InMemoryListener directly.
func (l *InmemoryListener) Dial() (net.Conn, error) {
	lisConn, dialConn := net.Pipe()
	l.connChan <- lisConn
	return dialConn, nil
}

// Addr returns the address of the listener.
func (l *InmemoryListener) Addr() net.Addr {
	return &addr{
		str: "inmemory",
	}
}
