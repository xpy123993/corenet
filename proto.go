package corenet

import (
	"encoding/json"
	"io"
)

// The following consts are general signals used by the package.
const (
	Nop = iota
	Dial
	Bind
	Serve
	Info
)

// GetCommandName returns the name of the signal.
func GetCommandName(Type int) string {
	switch Type {
	case Nop:
		return "Nop"
	case Dial:
		return "Dial"
	case Bind:
		return "Bind"
	case Serve:
		return "Serve"
	case Info:
		return "Info"
	default:
		return "Unknown"
	}
}

// SessionInfo stores all the available addresses of a session.
type SessionInfo struct {
	Channel   string
	Addresses []string `json:"addresses"`
}

// RelayRequest specifies a request to a relay server.
type RelayRequest struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// RelayResponse specifies a response from a relay server.
type RelayResponse struct {
	Success bool   `json:"success"`
	Payload string `json:"payload"`

	SessionInfo []SessionInfo `json:"session-info"`
}

// KCPConfig specifies kcp parameters.
type KCPConfig struct {
	MTU          int `default:"1350"`
	SndWnd       int `default:"2048"`
	RcvWnd       int `default:"2048"`
	DataShard    int `default:"10"`
	ParityShard  int `default:"3"`
	NoDelay      int `default:"1"`
	Interval     int `default:"10"`
	Resend       int `default:"2"`
	NoCongestion int `default:"1"`
}

// DefaultKCPConfig returns a default KCP config.
func DefaultKCPConfig() *KCPConfig {
	return &KCPConfig{
		MTU:          1350,
		SndWnd:       2048,
		RcvWnd:       2048,
		DataShard:    10,
		ParityShard:  3,
		NoDelay:      1,
		Interval:     10,
		Resend:       2,
		NoCongestion: 1,
	}
}

func getSessionInfo(conn io.ReadWriter) (*SessionInfo, error) {
	if _, err := conn.Write([]byte{Info}); err != nil {
		return nil, err
	}
	resp := SessionInfo{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
