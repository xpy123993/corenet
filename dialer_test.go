package corenet_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
)

func generateCertificate(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialID, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serialID,
		Subject: pkix.Name{
			CommonName: "test certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	certBytes := new(bytes.Buffer)
	if err := pem.Encode(certBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	keyBytes := new(bytes.Buffer)
	if err := pem.Encode(keyBytes, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}

	cert, err := tls.X509KeyPair(certBytes.Bytes(), keyBytes.Bytes())
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

func TestDialerUsePlainRelayProtocol(t *testing.T) {
	cert := generateCertificate(t)
	mainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer()
	go relayServer.Serve(mainListener, corenet.UsePlainRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("ttf://%s", mainListener.Addr().String())

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &tls.Config{
		InsecureSkipVerify: true,
	})
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
	}))
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
	expectID := fmt.Sprintf("relay://%s", mainListener.Addr().String())
	if !strings.Contains(sessionID, expectID) {
		t.Errorf("expect %s, got %v", expectID, sessionID)
	}
}

func TestDialerQuicBasedRelayProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayQuicListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer()
	go relayServer.Serve(relayListener, corenet.UseQuicRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("quicf://%s", relayListener.Addr().String())

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"quicf"},
	})
	if err != nil {
		t.Error(err)
	}
	clientListener := corenet.NewMultiListener(clientListenerAdapter)
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
	}))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
	conn.Close()

	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	expectID := fmt.Sprintf("relay://%s", relayListener.Addr().String())
	if !strings.Contains(sessionID, expectID) {
		t.Errorf("expect %s, got %v", expectID, sessionID)
	}
	wg.Wait()
}

func TestDialerListenerDifferentProtocol(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayQuicListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer()

	relayPlainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer relayPlainListener.Close()

	go relayServer.Serve(relayListener, corenet.UseQuicRelayProtocol())
	go relayServer.Serve(relayPlainListener, corenet.UsePlainRelayProtocol())

	time.Sleep(10 * time.Millisecond)

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(fmt.Sprintf("quicf://%s", relayListener.Addr().String()), "test-channel", &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"quicf"},
	})
	if err != nil {
		t.Error(err)
	}
	clientListener := corenet.NewMultiListener(clientListenerAdapter)
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
	dialer := corenet.NewDialer([]string{fmt.Sprintf("ttf://%s", relayPlainListener.Addr().String())}, corenet.WithDialerRelayTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}), corenet.WithDialerUpdateChannelAddress(false))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
	conn.Close()
	sessionID, err := dialer.GetSessionID("test-channel")
	if err != nil {
		t.Error(err)
	}
	expectID := fmt.Sprintf("relay://%s", relayPlainListener.Addr().String())
	if !strings.Contains(sessionID, expectID) {
		t.Errorf("expect %s, got %v", expectID, sessionID)
	}
	wg.Wait()
}

func TestDialerUpgradeSession(t *testing.T) {
	cert := generateCertificate(t)

	relayListener, err := corenet.CreateRelayQuicListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayServer := corenet.NewRelayServer()
	go relayServer.Serve(relayListener, corenet.UseQuicRelayProtocol())
	time.Sleep(3 * time.Millisecond)
	relayServerAddr := fmt.Sprintf("quicf://%s", relayListener.Addr().String())

	clientListenerAdapter, err := corenet.CreateListenerFallbackURLAdapter(relayServerAddr, "test-channel", &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"quicf"},
	})
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
		t.Errorf("expect %s to have tcp prefix", sessionID)
	}
	wg.Wait()
}
