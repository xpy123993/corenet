package corenet_test

import (
	"bufio"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
)

func echoLoop(t *testing.T, conn net.Conn) {
	type TestStruct struct {
		Data string
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := gob.NewEncoder(conn).Encode(TestStruct{Data: "helloworld"}); err != nil {
			t.Error(err)
		}
	}()
	res := TestStruct{}
	if err := gob.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Data != "helloworld" {
		t.Errorf("data mismatched")
	}
	wg.Wait()
}

func TestMultiListener(t *testing.T) {
	l1 := corenet.NewInMemoryListener()
	l2 := corenet.NewInMemoryListener()

	listener := corenet.NewMultiListener(
		corenet.WithListener(l1, []string{"test1"}),
		corenet.WithListener(l2, []string{"test2"}),
	)
	defer listener.Close()

	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				t.Error(err)
			}
			io.Copy(conn, conn)
		}
	}()

	conn, err := l1.Dial()
	if err != nil {
		t.Error(err)
	}
	conn.Write([]byte{corenet.Dial})
	echoLoop(t, conn)
	conn.Close()

	conn, err = l2.Dial()
	if err != nil {
		t.Error(err)
	}
	conn.Write([]byte{corenet.Dial})
	echoLoop(t, conn)
	conn.Close()
}

func TestListener(t *testing.T) {
	lis := corenet.NewInMemoryListener()
	l := corenet.NewMultiListener(corenet.WithListener(lis, []string{"test"}))
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		io.Copy(conn, conn)
	}()

	conn, err := lis.Dial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{corenet.Dial}); err != nil {
		t.Fatal(err)
	}
	echoLoop(t, conn)
}

func TestReverseListener(t *testing.T) {
	peerA, peerB := net.Pipe()
	dataA, dataB := net.Pipe()
	l := corenet.NewMultiListener(corenet.WithReverseListener(peerA, func() (net.Conn, error) {
		return dataA, nil
	}, []string{"reverse"}))
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		io.Copy(conn, bufio.NewReader(conn))
	}()

	if _, err := peerB.Write([]byte{corenet.Dial}); err != nil {
		t.Fatal(err)
	}
	echoLoop(t, dataB)
}

func TestBridgeListener(t *testing.T) {
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
	time.Sleep(30 * time.Millisecond)

	reverseListenerAdapter, err := corenet.CreateFallbackListener(fmt.Sprintf("ttf://%s", mainListener.Addr().String()), "test-channel", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientListener := corenet.NewMultiListener(reverseListenerAdapter)
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
	time.Sleep(30 * time.Millisecond)

	clientConn, err := tls.Dial("tcp", mainListener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	if err := json.NewEncoder(clientConn).Encode(corenet.BridgeRequest{Type: corenet.Dial, Payload: "test-channel"}); err != nil {
		t.Fatal(err)
	}
	resp := corenet.BridgeResponse{}
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if !resp.Success {
		t.Fatal(resp.Payload)
	}

	echoLoop(t, clientConn)

	clientListener.Close()
}
