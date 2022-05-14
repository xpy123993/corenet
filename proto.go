package corenet

const (
	Nop = iota
	Dial
	Bind
	Serve
	Info
)

type ListenerInfo struct {
	Addresses []string `json:"addresses"`
}

type BridgeRequest struct {
	Type    int
	Payload string
}

type BridgeResponse struct {
	Success bool
	Payload string
}
