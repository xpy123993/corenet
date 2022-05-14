package corenet

const (
	Nop = iota
	Dial
	Bind
	Serve
	Info
)

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

type ListenerInfo struct {
	Addresses []string `json:"addresses"`
}

type BridgeRequest struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

type BridgeResponse struct {
	Success bool   `json:"success"`
	Payload string `json:"payload"`
}
