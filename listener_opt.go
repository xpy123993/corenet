package corenet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	"github.com/lucas-clemente/quic-go"
	"github.com/xtaci/kcp-go"
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

// ListenerAdapter specifies a listener that can be used for multi-listener.
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

// WithListenerReverseConn returns a listener adapter that can be used for listener behaves like a client.
func WithListenerReverseConn(conn net.Conn, dialer func() (net.Conn, error), address []string) ListenerAdapter {
	return &listenerAdapterApplier{
		applyFn: func(ml *multiListener) {
			ml.addresses = append(ml.addresses, address...)
			ml.reverseListeners = append(ml.reverseListeners, &reverseListener{
				controlConn: conn,
				dialer:      dialer,
			})
		},
	}
}

// CreateListenerFallbackURLAdapter returns a listener adapter that listens on the specified relay server.
func CreateListenerFallbackURLAdapter(RelayServerURL string, Channel string, TLSConfig *tls.Config) (ListenerAdapter, error) {
	uri, err := url.Parse(RelayServerURL)
	if err != nil {
		return nil, err
	}
	if len(uri.Port()) == 0 {
		uri.Host = uri.Host + ":13300"
	}
	switch uri.Scheme {
	case "ttf":
		// tcp+tls+fallback
		return newClientListenerAdapter(uri.Host, Channel, func() (net.Conn, error) {
			return tls.Dial("tcp", uri.Host, TLSConfig)
		})
	case "ktf":
		// kcp+tls+fallback
		return newClientListenerAdapter(uri.Host, Channel, func() (net.Conn, error) {
			conn, err := kcp.Dial(uri.Host)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, TLSConfig), nil
		})
	case "quicf":
		// quic+fallback
		var tlsConfig tls.Config
		if TLSConfig != nil {
			tlsConfig = *TLSConfig
		}
		tlsConfig.NextProtos = append(TLSConfig.NextProtos, "quicf")
		return newQuicListenerAdapter(uri.Host, Channel, &tlsConfig, &quic.Config{
			KeepAlive: true,
		})
	default:
		return nil, fmt.Errorf("unknown protocol: %s", uri.Scheme)
	}
}

// CreateListenerTCPPortAdapter creates a listener adapter listening on local port `port`.
func CreateListenerTCPPortAdapter(port int) (ListenerAdapter, error) {
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
		addressWithProtocol = append(addressWithProtocol, fmt.Sprintf("tcp://%s:%d", address, openPort))
	}
	return WithListener(lis, addressWithProtocol), nil
}
