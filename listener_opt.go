package corenet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/quic-go/quic-go"
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
		if i.Flags&(net.FlagPointToPoint|net.FlagLoopback) != 0 {
			continue
		}
		if i.Flags&net.FlagUp == 0 {
			continue
		}
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
		QuicConfig: &quic.Config{KeepAlivePeriod: 20 * time.Second},
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
	if len(relayServerTLSConfig.ServerName) == 0 {
		relayServerTLSConfig.ServerName = uri.Hostname()
	}
	switch uri.Scheme {
	case "ttf":
		// tcp+tls+fallback
		return CreateSmuxListenerAdapter(func() (net.Conn, error) {
			conn, err := net.Dial("tcp", uri.Host)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(10 * time.Second)
			}
			return tls.Client(conn, relayServerTLSConfig), nil
		}, fmt.Sprintf("ttf://%s/%s", uri.Host, Channel), Channel)
	case "ktf":
		// kcp+tls+fallback
		kcpConfig := Options.KCPConfig
		if kcpConfig == nil {
			kcpConfig = DefaultKCPConfig()
		}
		dialer := func() (net.Conn, error) {
			return createKCPConnection(uri.Host, relayServerTLSConfig, kcpConfig)
		}
		return CreateSmuxListenerAdapter(dialer, fmt.Sprintf("ktf://%s/%s", uri.Host, Channel), Channel)
	case "udf":
		udpAddr, err := net.ResolveUDPAddr("udp", uri.Host)
		if err != nil {
			return nil, err
		}
		return CreateSmuxListenerAdapter(func() (net.Conn, error) {
			conn, err := dtls.Dial("udp", udpAddr, convertToDTLSConfig(relayServerTLSConfig))
			if err != nil {
				return nil, err
			}
			return newBufferedConn(conn), nil
		}, fmt.Sprintf("udf://%s/%s", uri.Host, Channel), Channel)
	case "quicf":
		// quic+fallback
		relayServerTLSConfig.NextProtos = append(Options.TLSConfig.NextProtos, "quicf")
		return newQuicListenerAdapter(uri.Host, Channel, relayServerTLSConfig, Options.QuicConfig)
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
