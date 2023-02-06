package corenet

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/lucas-clemente/quic-go"
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

// WithDialerRelayTLSConfig specifies the TLS configuration used to communicate with fallback server.
func WithDialerRelayTLSConfig(tlsConfig *tls.Config) DialerOption {
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

// WithDialerQuicConfig specifies the quic config being used for quicf protocol.
func WithDialerQuicConfig(config *quic.Config) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.quicConfig = config
		},
	}
}

// WithDialerKCPConfig specifies the kcp config being used for ktf protocol.
func WithDialerKCPConfig(config *KCPConfig) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.kcpConfig = config
		},
	}
}

// WithDialerLogError specifies whether to dump log errors.
func WithDialerLogError(v bool) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.logError = v
		},
	}
}

// WithDialerDirectAccessCIDRBlockList specifies the subnets that are not allowed for channel direct access.
// No affect if update channel is disabled.
func WithDialerDirectAccessCIDRBlockList(blocklist []netip.Prefix) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			d.channelCIDRblocklist = blocklist
		},
	}
}

// WithDialerBlockMultiListener add the listening address of a multi listener to its blocklist to avoid recusive connection.
func WithDialerBlockMultiListener(lis net.Listener) DialerOption {
	return &dialerOptionApplier{
		applyFn: func(d *Dialer) {
			mlis, ok := lis.(*multiListener)
			if !ok {
				return
			}
			for _, address := range mlis.addresses {
				d.connectionAddressBlocklist[address] = true
			}
		},
	}
}
