package corenet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/lucas-clemente/quic-go"
)

type listenerAdapterApplier struct {
	applyFn func(*multiListener)
	closeFn func() error
}

func (a *listenerAdapterApplier) applyTo(l *multiListener) {
	a.applyFn(l)
	a.closeFn = nil
}
func (a *listenerAdapterApplier) Close() error {
	if a.closeFn != nil {
		return a.closeFn()
	}
	return nil
}

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
	Close() error
}

// WithListener returns a listener adapter that can be used for multi listener.
func WithListener(listener net.Listener, address []string) ListenerAdapter {
	return &listenerAdapterApplier{
		applyFn: func(ml *multiListener) {
			ml.addresses = append(ml.addresses, address...)
			ml.listeners = append(ml.listeners, listener)
		},
		closeFn: listener.Close,
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
		closeFn: conn.Close,
	}
}

// ListenerFallbackOptions specifies the option needed for creating a fallback adapter.
type ListenerFallbackOptions struct {
	TLSConfig  *tls.Config
	KCPConfig  *KCPConfig
	QuicConfig *quic.Config
}

// CreateDefaultFallbackOptions returns a option with default value populated.
func CreateDefaultFallbackOptions() *ListenerFallbackOptions {
	return &ListenerFallbackOptions{
		TLSConfig:  nil,
		KCPConfig:  DefaultKCPConfig(),
		QuicConfig: &quic.Config{KeepAlive: true},
	}
}

// CreateListenerFallbackURLAdapter returns a listener adapter that listens on the specified relay server.
func CreateListenerFallbackURLAdapter(RelayServerURL string, Channel string, Options *ListenerFallbackOptions) (ListenerAdapter, error) {
	uri, err := url.Parse(RelayServerURL)
	if err != nil {
		return nil, err
	}
	if len(uri.Port()) == 0 {
		uri.Host = uri.Host + ":13300"
	}
	if Options == nil {
		Options = CreateDefaultFallbackOptions()
	}
	relayServerTLSConfig := Options.TLSConfig
	if relayServerTLSConfig == nil {
		relayServerTLSConfig = &tls.Config{}
	}
	relayServerTLSConfig.ServerName = uri.Hostname()
	switch uri.Scheme {
	case "ttf":
		// tcp+tls+fallback
		return newClientListenerAdapter(uri.Host, Channel, func() (net.Conn, error) {
			conn, err := net.Dial("tcp", uri.Host)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(10 * time.Second)
			}
			return tls.Client(conn, relayServerTLSConfig), nil
		})
	case "ktf":
		// kcp+tls+fallback
		kcpConfig := Options.KCPConfig
		if kcpConfig == nil {
			kcpConfig = DefaultKCPConfig()
		}
		return newKcpListenerAdapter(uri.Host, Channel, relayServerTLSConfig, kcpConfig)
	case "quicf":
		// quic+fallback
		relayServerTLSConfig.NextProtos = append(Options.TLSConfig.NextProtos, "quicf")
		return newQuicListenerAdapter(uri.Host, Channel, relayServerTLSConfig, Options.QuicConfig)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", uri.Scheme)
	}
}

// CreateListenerTCPPortAdapter creates a listener adapter listening on local port `port`.
func CreateListenerTCPPortAdapter(port int, tlsConfig *tls.Config) (ListenerAdapter, error) {
	lis, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
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
