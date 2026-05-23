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
// showMethod controls whether the icmp/tcp badge is shown — only needed in fallback mode.
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

// methodBadge returns a small colored tag showing how the host was found.
func methodBadge(h types.Host) string {
	switch h.Method {
	case types.MethodTCP:
		label := fmt.Sprintf("tcp:%s", h.Port)
		return lipgloss.NewStyle().
			Foreground(amber).
			Render(label)
	default:
		return lipgloss.NewStyle().
			Foreground(emerald).
			Render("icmp")
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
