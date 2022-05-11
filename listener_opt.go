package corenet

import (
	"fmt"
	"net"
)

type listenerAdapterApplier struct {
	applyFn func(*multiListener)
}

func (a *listenerAdapterApplier) applyTo(l *multiListener) { a.applyFn(l) }

type ListenerAdapter interface {
	applyTo(*multiListener)
}

func WithListener(listener net.Listener, address []string) ListenerAdapter {
	return &listenerAdapterApplier{
		applyFn: func(ml *multiListener) {
			ml.addresses = append(ml.addresses, address...)
			ml.listeners = append(ml.listeners, listener)
		},
	}
}

func CreateLocalListenerAdapter(network string, port int, address []string) (ListenerAdapter, error) {
	lis, err := net.Listen(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return &listenerAdapterApplier{
		applyFn: func(ml *multiListener) {
			ml.listeners = append(ml.listeners, lis)
			for _, addr := range address {
				ml.addresses = append(ml.addresses, fmt.Sprintf("%s://%s:%d", network, addr, port))
			}
		},
	}, nil
}
