package corenet

import (
	"encoding/json"
	"net"
	"sync"
)

func CreateListenerBaseBridgeProto(lis net.Listener) func(string, net.Conn) (Session, error) {
	mu := sync.Mutex{}
	connChanMap := make(map[string]chan net.Conn)
	go func() {
		for {
			bridgeConn, err := lis.Accept()
			if err != nil {
				for _, c := range connChanMap {
					close(c)
				}
				lis.Close()
				return
			}
			go func(bridgeConn net.Conn) {
				req := BridgeRequest{}
				if err := json.NewDecoder(bridgeConn).Decode(&req); err != nil {
					bridgeConn.Close()
					return
				}
				mu.Lock()
				connChan, exist := connChanMap[req.Payload]
				if !exist {
					connChanMap[req.Payload] = make(chan net.Conn)
					connChan = connChanMap[req.Payload]
				}
				mu.Unlock()
				connChan <- bridgeConn
			}(bridgeConn)
		}
	}()
	return func(s string, c net.Conn) (Session, error) {
		mu.Lock()
		connChan, exist := connChanMap[s]
		if !exist {
			connChanMap[s] = make(chan net.Conn)
			connChan = connChanMap[s]
		}
		mu.Unlock()
		return newReverseSession(c, connChan)
	}
}
