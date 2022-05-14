package corenet

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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

// WithReverseListener returns a listener adapter that can be used for listener behaves like a client.
func WithReverseListener(conn net.Conn, dialer func() (net.Conn, error), address []string) ListenerAdapter {
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

func CreatePlainBridgeListener(BridgeServerURL string, Channel string, TLSConfig *tls.Config) (ListenerAdapter, error) {
	uri, err := url.Parse(BridgeServerURL)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "ttf":
		// tcp+tls+fallback
		controlConn, err := tls.Dial("tcp", uri.Host, TLSConfig)
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(controlConn).Encode(BridgeRequest{Type: Bind, Payload: Channel}); err != nil {
			controlConn.Close()
			return nil, err
		}
		resp := BridgeResponse{}
		if err := json.NewDecoder(controlConn).Decode(&resp); err != nil {
			controlConn.Close()
			return nil, err
		}
		return WithReverseListener(controlConn, func() (net.Conn, error) {
			conn, err := tls.Dial("tcp", resp.Payload, TLSConfig)
			if err != nil {
				return nil, err
			}
			if err := json.NewEncoder(conn).Encode(BridgeRequest{Type: Bind, Payload: Channel}); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}, []string{BridgeServerURL}), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", uri.Scheme)
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
		addressWithProtocol = append(addressWithProtocol, fmt.Sprintf("tcp://%s:%d", address, openPort))
	}
	return WithListener(lis, addressWithProtocol), nil
}
