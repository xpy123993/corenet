package corenet

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/pion/dtls/v2"
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

func convertToDTLSConfig(config *tls.Config) *dtls.Config {
	dtlsConfig := &dtls.Config{
		Certificates:       config.Certificates,
		InsecureSkipVerify: config.InsecureSkipVerify,
		RootCAs:            config.RootCAs,
		ClientCAs:          config.ClientCAs,
		ServerName:         config.ServerName,
	}
	switch config.ClientAuth {
	case tls.NoClientCert:
		dtlsConfig.ClientAuth = dtls.NoClientCert
	case tls.RequestClientCert:
		dtlsConfig.ClientAuth = dtls.RequestClientCert
	case tls.RequireAndVerifyClientCert:
		dtlsConfig.ClientAuth = dtls.RequireAndVerifyClientCert
	case tls.RequireAnyClientCert:
		dtlsConfig.ClientAuth = dtls.RequireAnyClientCert
	case tls.VerifyClientCertIfGiven:
		dtlsConfig.ClientAuth = dtls.VerifyClientCertIfGiven
	default:
		log.Fatalf("Unexpected client auth type in dtls config: %v", dtlsConfig.ClientAuth)
	}
	return dtlsConfig
}

// bufferedConn is for packet conn to avoid dropping bytes while parsing.
type bufferedConn struct {
	net.Conn
	*bufio.Reader
}

func newBufferedConn(raw net.Conn) net.Conn {
	return &bufferedConn{Conn: raw, Reader: bufio.NewReader(raw)}
}

func (c *bufferedConn) Close() error {
	c.Reader.Discard(c.Reader.Buffered())
	return c.Conn.Close()
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *bufferedConn) WriteTo(writer io.Writer) (int64, error) {
	return c.Reader.WriteTo(writer)
}
