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

func TestBridgeProto(t *testing.T) {
	bridgeConnListener := corenet.NewInMemoryListener()
	bridgeListener := corenet.NewInMemoryListener()

	bridgeServer := corenet.NewBridgeServer(corenet.CreateListenerBaseBridgeProto(bridgeListener), "")
	go bridgeServer.Serve(bridgeConnListener)
	reverseListenerConn, err := bridgeConnListener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(reverseListenerConn).Encode(corenet.BridgeRequest{Type: corenet.Bind, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp := corenet.BridgeResponse{}
	if err := json.NewDecoder(reverseListenerConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	clientListener := corenet.NewMultiListener(corenet.WithReverseListener(reverseListenerConn, func() (net.Conn, error) {
		conn, err := bridgeListener.Dial()
		if err != nil {
			return nil, err
		}
		if err := json.NewEncoder(conn).Encode(corenet.BridgeRequest{Type: corenet.Bind, Payload: "test-channel"}); err != nil {
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

	clientConn := blockUntilDialSucceed(t, bridgeConnListener.Dial, time.Now().Add(time.Second))
	if err := json.NewEncoder(clientConn).Encode(&corenet.BridgeRequest{Type: corenet.Dial, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp = corenet.BridgeResponse{}
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatal(resp.Payload)
	}
	echoLoop(t, clientConn)
}
