package corenet

const (
	Nop = iota
	Dial
	Bind
	Info
)

type ListenerInfo struct {
	Addresses []string `json:"addresses"`
}
