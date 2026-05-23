package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/penguinshero/netprobe/internal/types"
)

var (
	purple     = lipgloss.Color("#7C3AED")
	softPurple = lipgloss.Color("#A78BFA")
	slate      = lipgloss.Color("#64748B")
	slateLight = lipgloss.Color("#94A3B8")
	emerald    = lipgloss.Color("#10B981")
	amber      = lipgloss.Color("#F59E0B")
	cyan       = lipgloss.Color("#06B6D4")
	white      = lipgloss.Color("#F1F5F9")
)

// PrintHeader renders the tool name and tagline.
func PrintHeader() {
	hex := lipgloss.NewStyle().Foreground(purple).Bold(true).Render("⬡")
	name := lipgloss.NewStyle().Foreground(white).Bold(true).Render("NetProbe")
	tag := lipgloss.NewStyle().Foreground(slate).Render("Speed with Intelligence — by Muhammad Shawon")
	fmt.Printf("\n  %s %s\n  %s\n\n", hex, name, tag)
}

// PrintTarget shows the interface and resolved CIDR before scanning starts.
func PrintTarget(iface, cidr string) {
	label := lipgloss.NewStyle().Foreground(slate).Render("  interface")
	target := lipgloss.NewStyle().Foreground(slate).Render("  target   ")
	ifaceVal := lipgloss.NewStyle().Foreground(slateLight).Render(iface)
	cidrVal := lipgloss.NewStyle().Foreground(white).Bold(true).Render(cidr)

	if iface != "" {
		fmt.Printf("%s  %s\n", label, ifaceVal)
	}
	fmt.Printf("%s  %s\n\n", target, cidrVal)
}

// PrintResults renders the discovered host list.
// showMethod controls the icmp/tcp badge — only useful in fallback mode.
func PrintResults(hosts []types.Host, showMethod bool) {
	if len(hosts) == 0 {
		fmt.Printf("\n  %s\n\n", lipgloss.NewStyle().Foreground(slate).Render("no live hosts found"))
		return
	}

	count := lipgloss.NewStyle().Foreground(softPurple).Bold(true).Render(fmt.Sprintf("%d", len(hosts)))
	label := lipgloss.NewStyle().Foreground(slate).Render(" host(s) discovered")
	fmt.Printf("  %s%s\n\n", count, label)

	for _, h := range hosts {
		dot := lipgloss.NewStyle().Foreground(emerald).Render("●")
		ip := lipgloss.NewStyle().Foreground(white).Bold(true).Width(16).Render(h.IP)

		line := fmt.Sprintf("  %s  %s", dot, ip)

		if showMethod {
			line += "  " + methodBadge(h)
		}

		if h.Hostname != "" {
			hostname := lipgloss.NewStyle().Foreground(slateLight).Render(h.Hostname)
			line += "  " + hostname
		}

		fmt.Println(line)
	}

	fmt.Println()
}

// PrintPortResults renders open ports in a clean aligned table.
func PrintPortResults(target string, ports []types.PortResult) {
	if len(ports) == 0 {
		fmt.Printf("\n  %s\n\n", lipgloss.NewStyle().Foreground(slate).Render("no open ports found"))
		return
	}

	tgt := lipgloss.NewStyle().Foreground(white).Bold(true).Render(target)
	count := lipgloss.NewStyle().Foreground(softPurple).Bold(true).Render(fmt.Sprintf("%d", len(ports)))
	label := lipgloss.NewStyle().Foreground(slate).Render(" open port(s) on ")
	fmt.Printf("\n  %s%s%s\n\n", count, label, tgt)

	colPort := lipgloss.NewStyle().Foreground(slate).Width(12).Render("PORT")
	colState := lipgloss.NewStyle().Foreground(slate).Width(10).Render("STATE")
	colService := lipgloss.NewStyle().Foreground(slate).Render("SERVICE")
	fmt.Printf("  %s%s%s\n", colPort, colState, colService)

	div := lipgloss.NewStyle().Foreground(lipgloss.Color("#1E293B")).Render("  ──────────────────────────────")
	fmt.Println(div)

	for _, p := range ports {
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		port := lipgloss.NewStyle().Foreground(cyan).Bold(true).Width(12).Render(portStr)
		state := lipgloss.NewStyle().Foreground(emerald).Width(10).Render(string(p.State))
		service := lipgloss.NewStyle().Foreground(slateLight).Render(p.Service)
		fmt.Printf("  %s%s%s\n", port, state, service)
	}

	fmt.Println()
}

// PrintHoneypotReport renders the honeypot analysis after port results.
func PrintHoneypotReport(r *types.HoneypotReport) {
	if r == nil || r.Confidence == "NONE" {
		return
	}

	// pick color based on confidence level
	var confColor lipgloss.Color
	switch r.Confidence {
	case "HIGH":
		confColor = lipgloss.Color("#EF4444")
	case "MEDIUM":
		confColor = lipgloss.Color("#F59E0B")
	default:
		confColor = lipgloss.Color("#94A3B8")
	}

	warn := lipgloss.NewStyle().Foreground(confColor).Bold(true).Render("⚠ honeypot indicators")
	conf := lipgloss.NewStyle().Foreground(confColor).Bold(true).Render(r.Confidence)
	fmt.Printf("  %s   confidence %s\n\n", warn, conf)

	labelStyle := lipgloss.NewStyle().Foreground(slate).Width(22)
	valStyle := lipgloss.NewStyle().Foreground(slateLight)
	flagStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render("[!]")
	okStyle := lipgloss.NewStyle().Foreground(emerald).Render("ok")

	// open ratio line
	ratioVal := valStyle.Render(fmt.Sprintf("%.0f%%", r.OpenRatio))
	ratioFlag := okStyle
	if r.RatioFlag {
		ratioFlag = flagStyle
	}
	fmt.Printf("  %s%s  %s\n", labelStyle.Render("open ratio"), ratioVal, ratioFlag)

	// response uniformity line
	uniVal := valStyle.Render(fmt.Sprintf("%.1fms variance", r.UniformityMS))
	uniFlag := okStyle
	if r.UniformityFlag {
		uniFlag = flagStyle
	}
	fmt.Printf("  %s%s  %s\n", labelStyle.Render("response uniformity"), uniVal, uniFlag)

	// banner check line
	bannerFlag := okStyle
	if r.BannerFlag {
		bannerFlag = flagStyle
		fmt.Printf("  %s%s  %s\n", labelStyle.Render("banner check"), valStyle.Render(r.BannerDetail), bannerFlag)
	} else {
		fmt.Printf("  %s%s  %s\n", labelStyle.Render("banner check"), valStyle.Render("no mismatch"), bannerFlag)
	}

	fmt.Println()
}

// methodBadge returns a small colored tag showing how the host was found.
func methodBadge(h types.Host) string {
	switch h.Method {
	case types.MethodTCP:
		return lipgloss.NewStyle().Foreground(amber).Render(fmt.Sprintf("tcp:%s", h.Port))
	default:
		return lipgloss.NewStyle().Foreground(emerald).Render("icmp")
	}
}

// — spinner —

type spinModel struct {
	sp      spinner.Model
	message string
}

func (m spinModel) Init() tea.Cmd { return m.sp.Tick }

func (m spinModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.sp, cmd = m.sp.Update(msg)
	return m, cmd
}

func (m spinModel) View() string {
	sp := lipgloss.NewStyle().Foreground(purple).Render(m.sp.View())
	msg := lipgloss.NewStyle().Foreground(slate).Render(m.message)
	return fmt.Sprintf("  %s  %s", sp, msg)
}

// Spinner starts an animated spinner and returns a stop function.
func Spinner(message string) func() {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = lipgloss.NewStyle().Foreground(purple)

	p := tea.NewProgram(spinModel{sp: sp, message: message}, tea.WithOutput(os.Stderr))

	done := make(chan struct{})
	go func() {
		p.Run()
		close(done)
	}()

	return func() {
		time.Sleep(80 * time.Millisecond)
		p.Quit()
		<-done
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}
