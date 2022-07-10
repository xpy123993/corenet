package corenet_test

import (
	"bufio"
	"encoding/gob"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"git.yuki.nu/corenet"
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
	l := corenet.NewMultiListener(corenet.WithListenerReverseConn(peerA, func() (net.Conn, error) {
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

func TestListenerClose(t *testing.T) {
	lis1 := corenet.NewInMemoryListener()
	lis2 := corenet.NewInMemoryListener()
	listener := corenet.NewMultiListener(
		corenet.WithListener(lis1, []string{"test1"}),
		corenet.WithListener(lis2, []string{"test2"}),
	)
	lis1.Close()
	time.Sleep(time.Millisecond)
	if !lis2.IsClosed() {
		t.Error("expect lis2 to be closed")
	}
	listener.Close()
}

func TestUnknownProtocol(t *testing.T) {
	_, err := corenet.CreateListenerFallbackURLAdapter("unknown://foobar", "foobar", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("expect an unknown protocol error, got %v", err)
	}
}

func TestListenerClientConnEmptyClose(t *testing.T) {
	inmemoryListener := corenet.NewInMemoryListener()
	listener := corenet.NewMultiListener(corenet.WithListener(inmemoryListener, []string{}))
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := listener.Accept()
		if err == nil {
			t.Error("expect an error here")
		}
	}()
	time.Sleep(time.Millisecond)

	conn, err := inmemoryListener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	listener.Close()
	wg.Wait()
}
