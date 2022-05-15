package corenet

import (
	"crypto/tls"
	"time"
)

type dialerOptionApplier struct {
	applyFn func(*Dialer)
}

func (a *dialerOptionApplier) applyTo(d *Dialer) { a.applyFn(d) }

// DialerOption specifies a dial option.
type DialerOption interface {
	applyTo(*Dialer)
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

// WithDialerUpdateChannelInterval specifies the interval to try to upgrade listener session to a higher priority.
// Only takes effect if update channel address is on, by default it will update every 30 seconds.
func WithDialerUpdateChannelInterval(duration time.Duration) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.updateChannelInterval = duration
		},
	}
}
