package corenet

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

// ListenerInfo stores all the available addresses of a multi-listener.
type ListenerInfo struct {
	Addresses []string `json:"addresses"`
}

// BridgeRequest specifies a request to a bridge server.
type BridgeRequest struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// BridgeResponse specifies a response from a bridge server.
type BridgeResponse struct {
	Success bool   `json:"success"`
	Payload string `json:"payload"`
}
