package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/xpy123993/corenet"
)

var (
	mode                  = flag.String("mode", "", "The mode of the binary, can be bridge, server or client.")
	bridgeServerURL       = flag.String("bridge-url", "", "The URL of bridge server.")
	bridgeServerPlainAddr = flag.String("bridge-plain-addr", "", "In bridge mode, the second listening address.")

	channel = flag.String("channel", "test-channel", "")
	message = flag.String("message", "hello world", "In client mode, the message sent to the server.")
)

func generateCertificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	serialID, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
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
		log.Fatal(err)
	}
	return cert
}

func main() {
	flag.Parse()

	switch *mode {
	case "bridge":
		serverURL, err := url.Parse(*bridgeServerURL)
		if err != nil {
			log.Fatal(err)
		}
		cert := generateCertificate()
		plainLis, err := tls.Listen("tcp", *bridgeServerPlainAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			log.Fatal(err)
		}
		mainLis, err := tls.Listen("tcp", serverURL.Host, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			log.Fatal(err)
		}
		bridgeServer := corenet.NewBridgeServer(corenet.CreateListenerBaseBridgeProto(plainLis), plainLis.Addr().String())
		if err := bridgeServer.Serve(mainLis); err != nil {
			log.Printf("Bridge server returns error: %v", err)
		}
	case "server":
		bridgeAdapter, err := corenet.CreatePlainBridgeListener(*bridgeServerURL, *channel, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Fatal(err)
		}
		listener := corenet.NewMultiListener(bridgeAdapter)
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("listener returns error: %v", err)
				return
			}
			go io.Copy(conn, conn)
		}
	case "client":
		dialer := corenet.NewDialer([]string{*bridgeServerURL}, corenet.WithDialerBridgeTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		conn, err := dialer.Dial(*channel)
		if err != nil {
			log.Printf("client dial failed: %v", err)
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(*message)); err != nil {
			log.Printf("client send data failed: %v", err)
			return
		}
		buf := make([]byte, len(*message)+10)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("client receive data failed: %v", err)
			return
		}
		log.Printf("result: %s", buf[:n])
	}
}
