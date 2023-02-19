package main

import (
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

func serveRelay() error {
	cert, _ := selfsign.GenerateSelfSigned()
	server := corenet.NewRelayServer(
		corenet.WithRelayServerForceEvictChannelSession(true),
		corenet.WithRelayServerLogError(true),
		corenet.WithRelayServerUnsecureSkipPeerContextCheck(true),
	)
	return server.ServeURL(*relayServerURL, &tls.Config{Certificates: []tls.Certificate{cert}})
}

func main() {
	flag.Parse()

	switch *mode {
	case "relay":
		if err := serveRelay(); err != nil {
			log.Printf("Relay server returns error: %v", err)
		}
	case "server":
		relayAdapter, err := corenet.CreateListenerFallbackURLAdapter(*relayServerURL, *channel, &corenet.ListenerFallbackOptions{TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		}})
		if err != nil {
			log.Fatal(err)
		}
		listener := corenet.NewMultiListener(relayAdapter)
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
		dialer := corenet.NewDialer([]string{*relayServerURL}, corenet.WithDialerRelayTLSConfig(&tls.Config{InsecureSkipVerify: true}), corenet.WithDialerUpdateChannelInterval(100*time.Millisecond))
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
