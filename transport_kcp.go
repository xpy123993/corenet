package corenet

import (
	"crypto/tls"
	"net"

	"github.com/xtaci/kcp-go/v5"
)

func applyKCPOpts(conn *kcp.UDPSession, config *KCPConfig) {
	conn.SetStreamMode(true)
	conn.SetMtu(config.MTU)
	conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	conn.SetWindowSize(config.SndWnd, config.RcvWnd)
}

// kcpListener is a wrapper to accept kcp connection and apply the corresponding config.
type kcpListener struct {
	*kcp.Listener
	config *KCPConfig
}

func (lis *kcpListener) Accept() (net.Conn, error) {
	conn, err := lis.AcceptKCP()
	if err != nil {
		return nil, err
	}
	applyKCPOpts(conn, lis.config)
	return conn, nil
}

// CreateRelayKCPListener creates a KCP listener for the relay service.
func CreateRelayKCPListener(Addr string, TLSConfig *tls.Config, KCPConfig *KCPConfig) (net.Listener, error) {
	lis, err := kcp.ListenWithOptions(Addr, nil, KCPConfig.DataShard, KCPConfig.ParityShard)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(&kcpListener{lis, KCPConfig}, TLSConfig), nil
}

func createKCPConnection(Addr string, TLSConfig *tls.Config, kcpConfig *KCPConfig) (net.Conn, error) {
	conn, err := kcp.DialWithOptions(Addr, nil, kcpConfig.DataShard, kcpConfig.ParityShard)
	if err != nil {
		return nil, err
	}
	applyKCPOpts(conn, kcpConfig)
	return tls.Client(conn, TLSConfig), nil
}
