package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/xpy123993/corenet"
)

var (
	mode           = flag.String("mode", "", "The mode of the binary, can be relay, server or client.")
	relayServerURL = flag.String("relay-url", "", "The URL of relay server.")

	channel = flag.String("channel", "test-channel", "")
	message = flag.String("message", "hello world", "In client mode, the message sent to the server.")
)

func serveRelay(cert tls.Certificate) error {
	server := corenet.NewRelayServer(
		corenet.WithRelayServerForceEvictChannelSession(true),
		corenet.WithRelayServerLogError(true),
	)
	return server.ServeURL(*relayServerURL, &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert})
}

func main() {
	flag.Parse()
	cert, _ := selfsign.GenerateSelfSigned()
	switch *mode {
	case "relay":
		if err := serveRelay(cert); err != nil {
			log.Printf("Relay server returns error: %v", err)
		}
	case "server":
		key := make([]byte, 32)
		rand.Read(key)
		directAdapter, err := corenet.CreateListenerAESTCPPortAdapter(0, key)
		if err != nil {
			log.Fatal(err)
		}
		relayAdapter, err := corenet.CreateListenerFallbackURLAdapter(*relayServerURL, *channel, &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}})
		if err != nil {
			log.Fatal(err)
		}
		listener := corenet.NewMultiListener(directAdapter, relayAdapter)
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
		dialer := corenet.NewDialer([]string{*relayServerURL}, corenet.WithDialerRelayTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}), corenet.WithDialerUpdateChannelInterval(100*time.Millisecond))
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
