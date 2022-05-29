package corenet_test

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
)

func blockUntilDialSucceed(t *testing.T, invoke func() (net.Conn, error), deadline time.Time) net.Conn {
	if time.Now().After(deadline) {
		t.Fatal("deadline exceeded")
	}
	if conn, err := invoke(); err == nil {
		return conn
	}
	time.Sleep(time.Millisecond)
	return blockUntilDialSucceed(t, invoke, deadline)
}

func TestRelayProto(t *testing.T) {
	relayConnListener := corenet.NewInMemoryListener()

	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(relayConnListener, corenet.UsePlainRelayProtocol())
	reverseListenerConn, err := relayConnListener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(reverseListenerConn).Encode(corenet.RelayRequest{Type: corenet.Bind, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp := corenet.RelayResponse{}
	if err := json.NewDecoder(reverseListenerConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	clientListener := corenet.NewMultiListener(corenet.WithListenerReverseConn(reverseListenerConn, func() (net.Conn, error) {
		conn, err := relayConnListener.Dial()
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(corenet.RelayRequest{Type: corenet.Serve, Payload: "test-channel"}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, []string{}))

	go func() {
		conn, err := clientListener.Accept()
		if err != nil {
			t.Error(err)
		}
		io.Copy(conn, conn)
	}()
	time.Sleep(time.Millisecond)

	clientConn := blockUntilDialSucceed(t, relayConnListener.Dial, time.Now().Add(time.Second))
	if err := json.NewEncoder(clientConn).Encode(&corenet.RelayRequest{Type: corenet.Dial, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp = corenet.RelayResponse{}
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatal(resp.Payload)
	}
	echoLoop(t, clientConn)
}

func TestRelayCrossProto(t *testing.T) {
	relayConnListener := corenet.NewInMemoryListener()
	relayConnListenerForClient := corenet.NewInMemoryListener()

	relayServer := corenet.NewRelayServer(corenet.WithRelayServerUnsecureSkipPeerContextCheck(true), corenet.WithRelayServerLogError(true))
	defer relayServer.Close()
	go relayServer.Serve(relayConnListener, corenet.UsePlainRelayProtocol())
	go relayServer.Serve(relayConnListenerForClient, corenet.UsePlainRelayProtocol())
	reverseListenerConn, err := relayConnListener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(reverseListenerConn).Encode(corenet.RelayRequest{Type: corenet.Bind, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp := corenet.RelayResponse{}
	if err := json.NewDecoder(reverseListenerConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	clientListener := corenet.NewMultiListener(corenet.WithListenerReverseConn(reverseListenerConn, func() (net.Conn, error) {
		conn, err := relayConnListener.Dial()
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(corenet.RelayRequest{Type: corenet.Serve, Payload: "test-channel"}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, []string{}))

	go func() {
		conn, err := clientListener.Accept()
		if err != nil {
			t.Error(err)
		}
		io.Copy(conn, conn)
	}()
	time.Sleep(time.Millisecond)

	clientConn := blockUntilDialSucceed(t, relayConnListenerForClient.Dial, time.Now().Add(time.Second))
	if err := json.NewEncoder(clientConn).Encode(&corenet.RelayRequest{Type: corenet.Dial, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp = corenet.RelayResponse{}
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatal(resp.Payload)
	}
	echoLoop(t, clientConn)
}
