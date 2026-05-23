package types

// Method tells us how we confirmed a host was alive.
type Method string

const (
	MethodICMP Method = "icmp"
	MethodTCP  Method = "tcp"
)

// Host is everything we know about a discovered address.
type Host struct {
	IP       string
	Hostname string
	Method   Method // how it was found — icmp or tcp:PORT
	Port     string // only set when Method is TCP
}
