package corenet_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/xpy123993/corenet"
)

func generateCertificate(t *testing.T) tls.Certificate {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestRawDialer(t *testing.T) {
	l1, err := corenet.CreateListenerTCPPortAdapter(0)
	if err != nil {
		t.Fatal(err)
	}
	listener := corenet.NewMultiListener(l1)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
		}
		io.Copy(conn, conn)
	}()

	dialer := corenet.NewDialer([]string{}, corenet.WithDialerChannelInitialAddress(map[string][]string{
		"test": strings.Split(listener.Addr().String(), ","),
	}))
	deadline := time.Now().Add(3 * time.Second)

	success := false
	for time.Now().Before(deadline) {
		conn, err := dialer.Dial("test")
		if err == nil {
			echoLoop(t, conn)
			success = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !success {
		t.Error("cannot reach to the test channel")
	}

	sessionID, err := dialer.GetSessionID("test")
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(listener.Addr().String(), sessionID) {
		t.Errorf("expect %s is one of %s", sessionID, listener.Addr().String())
	}
}

func TestDialerListenerDifferentProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayQuicListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))

	relayPlainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer relayPlainListener.Close()

	go relayServer.Serve(relayListener, corenet.UseQuicRelayProtocol())
	go relayServer.Serve(relayPlainListener, corenet.UseSmuxRelayProtocol())

	time.Sleep(10 * time.Millisecond)

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(fmt.Sprintf("quicf://%s", relayListener.Addr().String()), "test-channel", &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
	}})
	if err != nil {
		t.Error(err)
	}
	clientListener := corenet.NewMultiListener(clientListenerAdapter)
	defer clientListener.Close()
	time.Sleep(3 * time.Millisecond)
	dialer := corenet.NewDialer([]string{fmt.Sprintf("ttf://%s", relayPlainListener.Addr().String())}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}), corenet.WithDialerUpdateChannelAddress(false))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(sessionID, "ttf://") {
		t.Errorf("expect %s to be a ttf connection", sessionID)
	}
}

func TestDialerUpgradeSession(t *testing.T) {
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

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	directListenerAdapter := corenet.WithListener(lis, []string{fmt.Sprintf("tcp://%s", lis.Addr().String())})
	clientListener := corenet.NewMultiListener(directListenerAdapter, clientListenerAdapter)
	defer clientListener.Close()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := clientListener.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
		conn.Close()
	}()
	time.Sleep(3 * time.Millisecond)
	dialer := corenet.NewDialer([]string{relayServerAddr}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}), corenet.WithDialerUpdateChannelInterval(time.Millisecond))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
	conn.Close()

	time.Sleep(10 * time.Millisecond)
	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(sessionID, "tcp://") {
		t.Errorf("expect %s to be tcp connection", sessionID)
	}

	channelInfos, err := dialer.GetChannelInfosFromRelay()
	if err != nil {
		t.Error(err)
	}
	if len(channelInfos) != 1 {
		t.Errorf("expect 1 channel record, got: %v", channelInfos)
	}

	wg.Wait()
}

func TestDialerUpgradeSessionBlockedByListenerDirectAddress(t *testing.T) {
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

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directListenerAdapter := corenet.WithListener(lis, []string{fmt.Sprintf("tcp://%s", lis.Addr().String())})
	clientListener := corenet.NewMultiListener(directListenerAdapter, clientListenerAdapter)
	defer clientListener.Close()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := clientListener.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
		conn.Close()
	}()
	time.Sleep(3 * time.Millisecond)
	dialer := corenet.NewDialer([]string{relayServerAddr}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}), corenet.WithDialerUpdateChannelInterval(time.Millisecond),
		corenet.WithDialerBlockMultiListener(clientListener))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
	conn.Close()

	time.Sleep(10 * time.Millisecond)
	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(sessionID, "quicf://") {
		t.Errorf("expect %s to be quicf://", sessionID)
	}
	wg.Wait()
}

func TestDialerNoUpgradeSessionIfInBlocklist(t *testing.T) {
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

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	directListenerAdapter, err := corenet.CreateListenerTCPPortAdapter(0)
	if err != nil {
		t.Fatal(err)
	}
	clientListener := corenet.NewMultiListener(directListenerAdapter, clientListenerAdapter)
	defer clientListener.Close()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := clientListener.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
		conn.Close()
	}()
	time.Sleep(3 * time.Millisecond)
	dialer := corenet.NewDialer([]string{relayServerAddr}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}), corenet.WithDialerUpdateChannelInterval(time.Millisecond),
		corenet.WithDialerDirectAccessCIDRBlockList([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
	conn.Close()

	time.Sleep(10 * time.Millisecond)
	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(sessionID, "quicf://") {
		t.Errorf("expect %s is not changed", sessionID)
	}
	wg.Wait()
}
