package corenet

import (
	"io"
	"net"
	"sync"
)

type InmemoryListener struct {
	done     chan struct{}
	connChan chan net.Conn

	mu       sync.RWMutex
	isClosed bool
}

func NewInMemoryListener() *InmemoryListener {
	return &InmemoryListener{
		done:     make(chan struct{}),
		connChan: make(chan net.Conn),
		isClosed: false,
	}
}

func (l *InmemoryListener) IsClosed() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.isClosed
}

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

func (l *InmemoryListener) Dial() (net.Conn, error) {
	lisConn, dialConn := net.Pipe()
	l.connChan <- lisConn
	return dialConn, nil
}

func (l *InmemoryListener) Addr() net.Addr {
	return &addr{
		str: "inmemory",
	}
}
