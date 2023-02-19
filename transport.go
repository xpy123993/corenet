package corenet

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// KCPConfig specifies kcp parameters.
type KCPConfig struct {
	MTU          int `default:"1350"`
	SndWnd       int `default:"2048"`
	RcvWnd       int `default:"2048"`
	DataShard    int `default:"10"`
	ParityShard  int `default:"3"`
	NoDelay      int `default:"1"`
	Interval     int `default:"10"`
	Resend       int `default:"2"`
	NoCongestion int `default:"1"`
}

// DefaultKCPConfig returns a default KCP config.
func DefaultKCPConfig() *KCPConfig {
	return &KCPConfig{
		MTU:          1350,
		SndWnd:       2048,
		RcvWnd:       2048,
		DataShard:    10,
		ParityShard:  3,
		NoDelay:      1,
		Interval:     10,
		Resend:       2,
		NoCongestion: 1,
	}
}

func DefaultSmuxConfig() *smux.Config {
	return &smux.Config{
		Version:           1,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveDisabled: false,
		KeepAliveTimeout:  30 * time.Second,
		MaxFrameSize:      32 << 10,
		MaxReceiveBuffer:  8 << 20,
		MaxStreamBuffer:   4 << 20,
	}
}

func applyKCPOpts(conn *kcp.UDPSession, config *KCPConfig) {
	conn.SetStreamMode(true)
	conn.SetMtu(config.MTU)
	conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	conn.SetWindowSize(config.SndWnd, config.RcvWnd)
}

type hookedListener struct {
	net.Listener
	hook func(*hookedListener, net.Conn, error) (net.Conn, error)
}

func (lis *hookedListener) Accept() (net.Conn, error) {
	conn, err := lis.Listener.Accept()
	return lis.hook(lis, conn, err)
}

// CreateRelayKCPListener creates a KCP listener for the relay service.
func CreateRelayKCPListener(Addr string, TLSConfig *tls.Config, KCPConfig *KCPConfig) (net.Listener, error) {
	lis, err := kcp.ListenWithOptions(Addr, nil, KCPConfig.DataShard, KCPConfig.ParityShard)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(&hookedListener{Listener: lis, hook: func(hl *hookedListener, c net.Conn, err error) (net.Conn, error) {
		if err == nil {
			applyKCPOpts(c.(*kcp.UDPSession), KCPConfig)
		}
		return c, err
	}}, TLSConfig), nil
}

func CreateRelayUDPListener(Addr string, TLSConfig *tls.Config) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", Addr)
	if err != nil {
		return nil, err
	}
	lis, err := dtls.Listen("udp", udpAddr, convertToDTLSConfig(TLSConfig))
	if err != nil {
		return nil, err
	}
	return &hookedListener{
		Listener: lis,
		hook: func(hl *hookedListener, c net.Conn, err error) (net.Conn, error) {
			if err == nil {
				return newBufferedConn(c), nil
			}
			return nil, err
		},
	}, nil
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
