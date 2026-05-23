package scanner

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/penguinshero/netprobe/internal/types"
)

// AnalyzeHoneypot runs three checks and returns a confidence-scored report.
func AnalyzeHoneypot(target string, totalProbed int, openPorts []int, responseTimes []time.Duration) types.HoneypotReport {
	report := types.HoneypotReport{}

	// check 1 — open port ratio
	if totalProbed > 0 {
		report.OpenRatio = float64(len(openPorts)) / float64(totalProbed) * 100
		report.RatioFlag = report.OpenRatio >= 35
	}

	// check 2 — response time variance (too uniform = suspicious)
	if len(responseTimes) > 1 {
		variance := responseVarianceMS(responseTimes)
		report.UniformityMS = variance
		report.UniformityFlag = variance < 5.0 // under 5ms variance across all ports is unusual
	}

	// check 3 — banner mismatch on a sample of open ports
	mismatch, detail := checkBanners(target, openPorts)
	report.BannerFlag = mismatch
	report.BannerDetail = detail

	// score: each flag adds a point, map to confidence level
	score := 0
	if report.RatioFlag {
		score++
	}
	if report.UniformityFlag {
		score++
	}
	if report.BannerFlag {
		score++
	}

	switch score {
	case 1:
		report.Confidence = "LOW"
	case 2:
		report.Confidence = "MEDIUM"
	case 3:
		report.Confidence = "HIGH"
	default:
		report.Confidence = "NONE"
	}

	return report
}

// responseVarianceMS computes the standard deviation of response times in milliseconds.
func responseVarianceMS(times []time.Duration) float64 {
	if len(times) == 0 {
		return 0
	}

	var sum float64
	for _, t := range times {
		sum += float64(t.Milliseconds())
	}
	mean := sum / float64(len(times))

	var sqDiff float64
	for _, t := range times {
		diff := float64(t.Milliseconds()) - mean
		sqDiff += diff * diff
	}

	return math.Sqrt(sqDiff / float64(len(times)))
}

// checkBanners grabs banners from a small sample of open ports and checks
// whether the service response matches what we'd expect on that port.
func checkBanners(target string, openPorts []int) (bool, string) {
	// only sample the first few ports to avoid being noisy
	sample := openPorts
	if len(sample) > 5 {
		sample = sample[:5]
	}

	for _, port := range sample {
		banner := grabBanner(target, port)
		if banner == "" {
			continue
		}
		if mismatch := detectMismatch(port, banner); mismatch != "" {
			return true, mismatch
		}
	}

	return false, ""
}

// grabBanner connects to a port, reads the first response bytes, and returns them.
func grabBanner(target string, port int) string {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.ToLower(strings.TrimSpace(string(buf[:n])))
}

// detectMismatch returns a human-readable description if the banner
// doesn't match what we'd expect on a given port number.
func detectMismatch(port int, banner string) string {
	// map of ports to keywords we'd expect in a legitimate banner
	expected := map[int]string{
		22:   "ssh",
		21:   "ftp",
		25:   "smtp",
		110:  "pop3",
		143:  "imap",
		3306: "mysql",
	}

	keyword, known := expected[port]
	if !known {
		return ""
	}

	// if the banner exists but doesn't contain the expected keyword, flag it
	if banner != "" && !strings.Contains(banner, keyword) {
		return fmt.Sprintf("port %d → unexpected banner: %q", port, truncate(banner, 40))
	}

	return ""
}

// truncate shortens a string for display without breaking mid-word.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
