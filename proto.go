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
	Addresses []string `json:"addresses"`
}

// RelayRequest specifies a request to a relay server.
type RelayRequest struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`

	DialGetSessionInfo bool `json:"get-sesion-info"`
}

// RelayResponse specifies a response from a relay server.
type RelayResponse struct {
	Success bool   `json:"success"`
	Payload string `json:"payload"`

	SessionInfo SessionInfo `json:"session-info"`
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
