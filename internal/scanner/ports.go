package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/penguinshero/netprobe/internal/types"
	"github.com/penguinshero/netprobe/internal/ui"
)

// wellKnown maps port numbers to their common service names.
var wellKnown = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
	110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc", 139: "netbios",
	143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
	445: "smb", 465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin",
	514: "syslog", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 990: "ftps",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
	1900: "upnp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
	2376: "docker-tls", 2379: "etcd", 3000: "grafana", 3306: "mysql",
	3389: "rdp", 3690: "svn", 4444: "metasploit", 5000: "flask",
	5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
	5984: "couchdb", 6379: "redis", 6443: "k8s-api", 7001: "weblogic",
	7474: "neo4j", 8080: "http-alt", 8443: "https-alt", 8500: "consul",
	8888: "jupyter", 8983: "solr", 9000: "sonarqube", 9042: "cassandra",
	9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
	9300: "elasticsearch-cluster", 9418: "git", 10250: "kubelet",
	11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 50070: "hadoop",
}

// top1000 holds the most commonly seen ports ordered roughly by prevalence.
var top1000 = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017,
	20, 69, 79, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109,
	113, 119, 125, 135, 139, 143, 161, 179, 199, 389, 406, 427, 444,
	464, 465, 497, 500, 512, 513, 514, 515, 524, 543, 544, 548, 554,
	563, 587, 593, 631, 636, 646, 683, 700, 749, 783, 800, 843, 873,
	880, 888, 902, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
	1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1110,
	1234, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
	2121, 2181, 2375, 2376, 2379, 2380, 3000, 3001, 3128, 3306, 3389,
	3690, 4000, 4001, 4040, 4443, 4444, 4567, 4848, 5000, 5001, 5432,
	5601, 5672, 5900, 5984, 6000, 6379, 6443, 7001, 7474, 7777, 8000,
	8001, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
	8089, 8090, 8443, 8500, 8800, 8880, 8888, 8983, 9000, 9001, 9042,
	9090, 9091, 9092, 9200, 9300, 9418, 9999, 10000, 10250, 11211,
	15672, 27017, 27018, 28017, 50000, 50070, 61616,
}

// portJob carries a port number and its assigned send time for rate limiting.
type portJob struct {
	port     int
	sendAt   time.Time
}

// portResult is the raw output from a single probe, including timing.
type portResult struct {
	types.PortResult
	responseTime time.Duration
}

// ScanPorts probes the given ports on a target with full intelligence:
// randomized order, jitter, rate limiting, and optional honeypot detection.
func ScanPorts(target string, ports []int, cfg ScanConfig, honeypot bool) ([]types.PortResult, *types.HoneypotReport, error) {
	// shuffle port order so sequential scanning patterns don't appear
	shuffled := shufflePorts(ports)

	jobs := buildJobs(shuffled, cfg)

	results := make(chan portResult, len(ports))
	var wg sync.WaitGroup

	sem := make(chan struct{}, cfg.Threads)

	stop := ui.Spinner(fmt.Sprintf("Scanning %s  [%s]", target, cfg.Preset))

	for _, job := range jobs {
		wg.Add(1)
		go func(j portJob) {
			defer wg.Done()

			// wait until this job's scheduled send time
			now := time.Now()
			if j.sendAt.After(now) {
				time.Sleep(j.sendAt.Sub(now))
			}

			sem <- struct{}{}
			results <- probePort(target, j.port, cfg.Timeout)
			<-sem
		}(job)
	}

	wg.Wait()
	close(results)
	stop()

	// separate open ports and collect timing data for honeypot analysis
	var open []types.PortResult
	var openPortNums []int
	var responseTimes []time.Duration

	for r := range results {
		responseTimes = append(responseTimes, r.responseTime)
		if r.State == types.PortOpen {
			open = append(open, r.PortResult)
			openPortNums = append(openPortNums, r.Port)
		}
	}

	// sort open ports so output reads top to bottom cleanly
	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})

	var report *types.HoneypotReport
	if honeypot && len(open) > 0 {
		r := AnalyzeHoneypot(target, len(ports), openPortNums, responseTimes)
		report = &r
	}

	return open, report, nil
}

// probePort attempts a TCP connect and records how long it took.
func probePort(target string, port int, timeout time.Duration) portResult {
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)

	result := portResult{
		PortResult: types.PortResult{
			Port:    port,
			Proto:   "tcp",
			State:   types.PortClosed,
			Service: wellKnown[port],
		},
		responseTime: elapsed,
	}

	if err == nil {
		conn.Close()
		result.State = types.PortOpen
	}

	return result
}

// buildJobs assigns a scheduled send time to each port based on rate limiting and jitter.
func buildJobs(ports []int, cfg ScanConfig) []portJob {
	jobs := make([]portJob, len(ports))

	// interval between packets to stay within the configured rate
	interval := time.Second / time.Duration(cfg.Rate)

	for i, port := range ports {
		delay := time.Duration(i) * interval

		// add random jitter (up to 50% of the interval) when enabled
		if cfg.Jitter {
			jitter := time.Duration(rand.Int63n(int64(interval / 2)))
			delay += jitter
		}

		jobs[i] = portJob{
			port:   port,
			sendAt: time.Now().Add(delay),
		}
	}

	return jobs
}

// shufflePorts returns a randomized copy of the port list.
func shufflePorts(ports []int) []int {
	out := make([]int, len(ports))
	copy(out, ports)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// TopPorts returns the deduplicated top 1000 port list.
func TopPorts() []int {
	seen := make(map[int]bool, len(top1000))
	unique := make([]int, 0, len(top1000))
	for _, p := range top1000 {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// ParsePorts turns user input into a slice of port numbers.
// Accepts: "22,80,443"  |  "1-1000"  |  "-" (all ports)
func ParsePorts(input string) ([]int, error) {
	input = strings.TrimSpace(input)

	if input == "-" {
		return allPorts(), nil
	}

	// "1-1000" style range — must not contain commas
	if strings.Contains(input, "-") && !strings.Contains(input, ",") {
		parts := strings.SplitN(input, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid range %q — use format like 1-1000", input)
		}
		ports := make([]int, 0, end-start+1)
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	// "22,80,443" comma-separated list
	parts := strings.Split(input, ",")
	var ports []int
	for _, part := range parts {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// allPorts returns every valid TCP port number.
func allPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}
