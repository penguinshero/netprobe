package scanner

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/penguinshero/netprobe/internal/network"
	"github.com/penguinshero/netprobe/internal/types"
	"github.com/penguinshero/netprobe/internal/ui"
)

const (
	// small pause between ICMP packets so we don't flood the segment
	sendDelay = 2 * time.Millisecond

	// window to collect replies after the last echo is sent
	icmpWindow = 2 * time.Second

	// per-connection timeout for TCP fallback probes
	tcpTimeout = 800 * time.Millisecond
)

// ports we try when a host didn't respond to ICMP.
// ordered by how commonly they're open across different device types.
var fallbackPorts = []string{"22", "80", "443", "8080", "8443"}

// DiscoverHosts runs an ICMP scan across the given CIDR.
// when fallback is true, hosts that ignored ICMP are re-probed via TCP.
func DiscoverHosts(cidr string, fallback bool) ([]types.Host, error) {
	targets, err := network.ExpandHosts(cidr)
	if err != nil {
		return nil, err
	}

	stop := ui.Spinner("Scanning " + cidr)

	alive, missed := icmpScan(targets)

	if fallback && len(missed) > 0 {
		tcpHosts := tcpScan(missed)
		alive = append(alive, tcpHosts...)
	}

	stop()
	return alive, nil
}

// icmpScan sends echo requests to every target using a shared raw socket.
// returns confirmed hosts and a slice of IPs that never replied.
func icmpScan(targets []string) ([]types.Host, []string) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		printCapWarning()
		os.Exit(1)
	}
	defer conn.Close()

	// each IP gets its own reply channel
	pending := make(map[string]chan struct{}, len(targets))
	for _, ip := range targets {
		pending[ip] = make(chan struct{}, 1)
	}

	var mu sync.Mutex
	go readICMPReplies(conn, pending, &mu)

	for i, ip := range targets {
		sendEcho(conn, ip, i+1)
		time.Sleep(sendDelay)
	}

	time.Sleep(icmpWindow)

	var alive []types.Host
	var missed []string

	mu.Lock()
	for _, ip := range targets {
		ch := pending[ip]
		select {
		case <-ch:
			alive = append(alive, types.Host{
				IP:       ip,
				Hostname: reverseLookup(ip),
				Method:   types.MethodICMP,
			})
		default:
			missed = append(missed, ip)
		}
	}
	mu.Unlock()

	return alive, missed
}

// tcpScan probes a list of IPs across common ports.
// any host that accepts a connection on any port is considered alive.
func tcpScan(targets []string) []types.Host {
	results := make(chan types.Host, len(targets))
	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if h, ok := tcpProbe(ip); ok {
				results <- h
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	var hosts []types.Host
	for h := range results {
		hosts = append(hosts, h)
	}
	return hosts
}

// tcpProbe tries each fallback port and returns on the first one that connects.
func tcpProbe(ip string) (types.Host, bool) {
	for _, port := range fallbackPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), tcpTimeout)
		if err == nil {
			conn.Close()
			return types.Host{
				IP:       ip,
				Hostname: reverseLookup(ip),
				Method:   types.MethodTCP,
				Port:     port,
			}, true
		}
	}
	return types.Host{}, false
}

// sendEcho writes one ICMP echo request to the destination IP.
func sendEcho(conn *icmp.PacketConn, ip string, seq int) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("netprobe"),
		},
	}
	raw, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	conn.WriteTo(raw, &net.IPAddr{IP: net.ParseIP(ip)})
}

// readICMPReplies runs in its own goroutine, routing every echo reply
// to the channel of the IP it came from.
func readICMPReplies(conn *icmp.PacketConn, pending map[string]chan struct{}, mu *sync.Mutex) {
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		src := peer.String()
		mu.Lock()
		ch, found := pending[src]
		mu.Unlock()

		if found {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// reverseLookup does a PTR query; silently returns empty on failure.
func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// printCapWarning is shown when the binary can't open a raw socket.
func printCapWarning() {
	fmt.Println("\n  [netprobe] permission denied — ICMP needs cap_net_raw")
	fmt.Println("  fix it once with:")
	fmt.Println("    sudo setcap cap_net_raw+ep ./netprobe\n")
}
