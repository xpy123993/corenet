package corenet

import "crypto/tls"

type dialerOptionApplier struct {
	applyFn func(*Dialer)
}

func (a *dialerOptionApplier) applyTo(d *Dialer) { a.applyFn(d) }

// DialerOption specifies a dial option.
type DialerOption interface {
	applyTo(*Dialer)
}

// WithDialerFallbackChannel adds more fallback addresses to the dialer.
func WithDialerFallbackChannel(address ...string) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.fallbackAddress = address
		},
	}
}

// WithDialerChannelInitialAddress specifies the initial channel addresses before reaching out to any fallback servers.
func WithDialerChannelInitialAddress(address map[string][]string) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.channelAddresses = address
		},
	}
}

// WithDialerUpdateChannelAddress specfies whether the dialer should automatically update the channel addresses.
func WithDialerUpdateChannelAddress(v bool) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.updateChannelAddress = v
		},
	}
}

// WithDialerBridgeTLSConfig specifies the TLS configuration used to communicate with fallback server.
func WithDialerBridgeTLSConfig(tlsConfig *tls.Config) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.tlsConfig = tlsConfig
		},
	}
}
