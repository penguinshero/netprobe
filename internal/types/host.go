package types

// Method tells us how we confirmed a host was alive during discovery.
type Method string

const (
	MethodICMP Method = "icmp"
	MethodTCP  Method = "tcp"
)

// Host represents a single discovered device on the network.
type Host struct {
	IP       string
	Hostname string
	Method   Method
	Port     string
}

// PortState describes the result of probing a single port.
type PortState string

const (
	PortOpen   PortState = "open"
	PortClosed PortState = "closed"
)

// PortResult holds everything we know about a scanned port.
type PortResult struct {
	Port    int
	Proto   string
	State   PortState
	Service string
}

// HoneypotReport holds the analysis result for a scanned target.
type HoneypotReport struct {
	Confidence     string // NONE, LOW, MEDIUM, HIGH
	OpenRatio      float64
	RatioFlag      bool
	UniformityMS   float64
	UniformityFlag bool
	BannerFlag     bool
	BannerDetail   string
}
