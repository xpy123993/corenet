package corenet

import (
	"fmt"
	"net"
)

type listenerAdapterApplier struct {
	applyFn func(*multiListener)
}

func (a *listenerAdapterApplier) applyTo(l *multiListener) { a.applyFn(l) }

func getAllAccessibleIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ret = append(ret, ip.String())
		}
	}
	return ret, nil
}

type ListenerAdapter interface {
	applyTo(*multiListener)
}

// WithListener returns a listener adapter that can be used for multi listener.
func WithListener(listener net.Listener, address []string) ListenerAdapter {
	return &listenerAdapterApplier{
		applyFn: func(ml *multiListener) {
			ml.addresses = append(ml.addresses, address...)
			ml.listeners = append(ml.listeners, listener)
		},
	}
}

// CreateTCPPortListenerAdapter creates a listener adapter listening on local port `port`.
func CreateTCPPortListenerAdapter(port int) (ListenerAdapter, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	addresses, err := getAllAccessibleIPs()
	if err != nil {
		return nil, err
	}
	openPort := lis.Addr().(*net.TCPAddr).Port
	addressWithProtocol := make([]string, 0, len(addresses))
	for _, address := range addresses {
		addressWithProtocol = append(addressWithProtocol, fmt.Sprintf("raw://%s:%d", address, openPort))
	}
	return WithListener(lis, addressWithProtocol), nil
}
