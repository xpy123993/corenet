package corenet

import "crypto/tls"

type dialerOptionApplier struct {
	applyFn func(*Dialer)
}

func (a *dialerOptionApplier) applyTo(d *Dialer) { a.applyFn(d) }

type DialerOption interface {
	applyTo(*Dialer)
}

func WithDialerFallbackChannel(address ...string) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.fallbackAddress = address
		},
	}
}

func WithDialerChannelInitialAddress(address map[string][]string) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.channelAddresses = address
		},
	}
}

func WithDialerUpdateChannelAddress(v bool) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.updateChannelAddress = v
		},
	}
}

func WithDialerBridgeTLSConfig(tlsConfig *tls.Config) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.tlsConfig = tlsConfig
		},
	}
}
