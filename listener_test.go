package corenet_test

import (
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
)

func echoLoop(t *testing.T, conn net.Conn) {
	type TestStruct struct {
		Data string
	}
	if err := gob.NewEncoder(conn).Encode(TestStruct{Data: "helloworld"}); err != nil {
		t.Fatal(err)
	}
	res := TestStruct{}
	if err := gob.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Data != "helloworld" {
		t.Errorf("data mismatched")
	}
}

func blockUntilAccessible(address string, deadline time.Time) error {
	if time.Now().After(deadline) {
		return fmt.Errorf("deadline exceeded")
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		time.Sleep(time.Millisecond)
		return blockUntilAccessible(address, deadline)
	}
	conn.Close()
	return nil
}

func TestMultiListener(t *testing.T) {
	l1, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	listener := corenet.NewMultiListener(
		corenet.WithListener(l1, []string{"test1"}),
		corenet.WithListener(l2, []string{"test1"}),
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

	if err := blockUntilAccessible(l1.Addr().String(), time.Now().Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", l1.Addr().String())
	if err != nil {
		t.Error(err)
	}
	conn.Write([]byte{corenet.Dial})
	echoLoop(t, conn)
	conn.Close()

	conn, err = net.Dial("tcp", l2.Addr().String())
	if err != nil {
		t.Error(err)
	}
	conn.Write([]byte{corenet.Dial})
	echoLoop(t, conn)
	conn.Close()
}
