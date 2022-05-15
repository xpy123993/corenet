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
	l1, err := corenet.CreateTCPPortListenerAdapter(0)
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
}

func TestDialerBridge(t *testing.T) {
	cert := generateCertificate(t)
	mainListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	bridgeListener, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge := corenet.NewBridgeServer(corenet.CreateBridgeListenerBasedFallback(bridgeListener), bridgeListener.Addr().String())
	go bridge.Serve(mainListener)
	time.Sleep(3 * time.Millisecond)
	bridgeServerAddr := fmt.Sprintf("ttf://%s", mainListener.Addr().String())

	clientListenerAdapter, err := corenet.CreateFallbackListener(bridgeServerAddr, "test-channel", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Error(err)
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

	dialer := corenet.NewDialer([]string{bridgeServerAddr}, corenet.WithDialerBridgeTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	}))
	conn, err := dialer.Dial("test-channel")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoLoop(t, conn)
}

func TestDialerBridgeQuic(t *testing.T) {
	cert := generateCertificate(t)

	bridgeListener, err := corenet.CreateBridgeServeListener(":0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quicf"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bridge := corenet.NewBridgeServer(corenet.CreateBridgeQuicFallback(), bridgeListener.Addr().String())
	go bridge.Serve(bridgeListener)
	time.Sleep(3 * time.Millisecond)
	bridgeServerAddr := fmt.Sprintf("quicf://%s", bridgeListener.Addr().String())

	clientListenerAdapter, err := corenet.CreateFallbackListener(bridgeServerAddr, "test-channel", &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"quicf"},
	})
	if err != nil {
		t.Error(err)
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
	dialer := corenet.NewDialer([]string{bridgeServerAddr}, corenet.WithDialerBridgeTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicf"},
	}))
	{
		conn, err := dialer.Dial("test-channel")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		echoLoop(t, conn)
	}
}
