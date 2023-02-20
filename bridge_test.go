package corenet_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
)

func listenerDialerRoutine(t *testing.T, relayServerAddr, expectSessionID string) {
	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
	}})
	if err != nil {
		t.Error(err)
		return
	}
	clientListener := corenet.NewMultiListener(clientListenerAdapter)
	defer clientListener.Close()
	go func() {
		for {
			conn, err := clientListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				io.Copy(conn, conn)
				conn.Close()
			}(conn)
		}
	}()
	time.Sleep(3 * time.Millisecond)

	dialer := corenet.NewDialer([]string{relayServerAddr}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	}), corenet.WithDialerLogError(true))
	defer dialer.Close()
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoLoop(t, conn)

	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(sessionID, expectSessionID) {
		t.Errorf("expect %s, got %v", expectSessionID, sessionID)
	}
}

func TestDialerUsePlainRelayTCPProtocol(t *testing.T) {
	cert := generateCertificate(t)
	mainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(mainListener, corenet.UseSmuxRelayProtocol())
	time.Sleep(10 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("ttf://%s", mainListener.Addr().String())

	listenerDialerRoutine(t, relayServerAddr, relayServerAddr)
}

func TestDialerUseRelayTCPProtocolChannelNotExists(t *testing.T) {
	cert := generateCertificate(t)
	mainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(mainListener, corenet.UseSmuxRelayProtocol())
	time.Sleep(10 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("ttf://%s", mainListener.Addr().String())

	dialer := corenet.NewDialer([]string{relayServerAddr}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	}))
	_, err = dialer.Dial("test-channel")
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expect an unavailable error, got %v", err)
	}
}

func TestDialerQuicBasedRelayProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayQuicListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(relayListener, corenet.UseQuicRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("quicf://%s", relayListener.Addr().String())

	listenerDialerRoutine(t, relayServerAddr, relayServerAddr)
}

func TestDialerKCPRelayProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayKCPListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}}, corenet.DefaultKCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(relayListener, corenet.UseSmuxRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("ktf://%s", relayListener.Addr().String())

	listenerDialerRoutine(t, relayServerAddr, relayServerAddr)
}

func TestDialerUDFRelayProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayUDPListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(relayListener, corenet.UseSmuxRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("udf://%s", relayListener.Addr().String())

	listenerDialerRoutine(t, relayServerAddr, relayServerAddr)
}
