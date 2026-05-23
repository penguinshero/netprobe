package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/penguinshero/netprobe/internal/network"
	"github.com/penguinshero/netprobe/internal/scanner"
	"github.com/penguinshero/netprobe/internal/ui"
	"github.com/spf13/cobra"
)

// discovery flags
var iface    string
var cidr     string
var fallback bool

// port scan flags
var target         string
var ports          string
var useTop         bool
var preset         string
var fast           bool
var honeypotDetect bool

var root = &cobra.Command{
	Use:           "netprobe",
	Short:         "",
	RunE:          run,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := root.Execute(); err != nil {
		errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444"))
		fmt.Fprintln(os.Stderr, errStyle.Render("  error: "+err.Error()))
		os.Exit(1)
	}
}

func init() {
	root.Flags().StringVarP(&iface, "interface", "i", "", "Network interface to scan (e.g. eth0, wlan0)")
	root.Flags().StringVarP(&cidr, "range", "r", "", "Target subnet in CIDR notation (e.g. 192.168.1.0/24)")
	root.Flags().BoolVarP(&fallback, "fallback", "f", false, "TCP fallback for ICMP-filtered hosts")

	root.Flags().StringVarP(&target, "target", "t", "", "Target IP for port scanning")
	root.Flags().StringVarP(&ports, "ports", "p", "", "Ports: 22,80  |  1-1000  |  - (all)")
	root.Flags().BoolVar(&useTop, "top", false, "Scan top 1000 common ports")
	root.Flags().StringVar(&preset, "preset", "lan", "Scan preset: lan | public")
	root.Flags().BoolVar(&fast, "fast", false, "Faster scan for public targets (use with --preset public)")
	root.Flags().BoolVar(&honeypotDetect, "honeypot-detect", false, "Analyze results for honeypot indicators")

	root.SetUsageFunc(customUsage)
}

func run(cmd *cobra.Command, args []string) error {
	if target != "" {
		return runPortScan()
	}
	if iface != "" || cidr != "" {
		return runDiscovery()
	}
	return cmd.Help()
}

func runDiscovery() error {
	ui.PrintHeader()

	var subnet string
	if cidr != "" {
		subnet = cidr
	} else {
		resolved, err := network.SubnetFromInterface(iface)
		if err != nil {
			return fmt.Errorf("could not resolve interface %q: %w", iface, err)
		}
		subnet = resolved
	}

	ui.PrintTarget(iface, subnet)

	hosts, err := scanner.DiscoverHosts(subnet, fallback)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	ui.PrintResults(hosts, fallback)
	return nil
}

func runPortScan() error {
	ui.PrintHeader()

	// build the port list from whichever flag the user passed
	var portList []int
	var err error

	switch {
	case useTop:
		portList = scanner.TopPorts()
	case ports != "":
		portList, err = scanner.ParsePorts(ports)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("specify ports with -p or use --top")
	}

	// apply the chosen preset and optional --fast modifier
	cfg := scanner.DefaultConfig()
	scanner.ApplyPreset(&cfg, preset, fast)

	results, report, err := scanner.ScanPorts(target, portList, cfg, honeypotDetect)
	if err != nil {
		return fmt.Errorf("port scan failed: %w", err)
	}

	ui.PrintPortResults(target, results)
	ui.PrintHoneypotReport(report)

	return nil
}

// customUsage prints discovery and port scanning flags in two clear sections.
func customUsage(cmd *cobra.Command) error {
	ac := lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
	dm := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B"))
	fl := lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))

	fmt.Println(buildBanner())
	fmt.Println()
	fmt.Printf("  %s\n", dm.Render("Usage:"))
	fmt.Printf("    netprobe [flags]\n\n")

	fmt.Printf("  %s\n", ac.Render("Discovery:"))
	fmt.Printf("    %s  %s\n", fl.Render("-i, --interface        "), dm.Render("Network interface to scan (e.g. eth0, wlan0)"))
	fmt.Printf("    %s  %s\n", fl.Render("-r, --range            "), dm.Render("Target subnet in CIDR notation (e.g. 192.168.1.0/24)"))
	fmt.Printf("    %s  %s\n", fl.Render("-f, --fallback         "), dm.Render("TCP fallback for ICMP-filtered hosts"))
	fmt.Println()

	fmt.Printf("  %s\n", ac.Render("Port Scanning:"))
	fmt.Printf("    %s  %s\n", fl.Render("-t, --target           "), dm.Render("Target IP address"))
	fmt.Printf("    %s  %s\n", fl.Render("-p, --ports            "), dm.Render("Ports: 22,80  |  1-1000  |  - (all)"))
	fmt.Printf("    %s  %s\n", fl.Render("    --top              "), dm.Render("Scan top 1000 common ports"))
	fmt.Printf("    %s  %s\n", fl.Render("    --preset           "), dm.Render("Scan profile: lan (default) | public"))
	fmt.Printf("    %s  %s\n", fl.Render("    --fast             "), dm.Render("Increase speed for public targets"))
	fmt.Printf("    %s  %s\n", fl.Render("    --honeypot-detect  "), dm.Render("Analyze results for honeypot indicators"))
	fmt.Println()

	fmt.Printf("  %s\n", ac.Render("Other:"))
	fmt.Printf("    %s  %s\n", fl.Render("-h, --help             "), dm.Render("Help for netprobe"))
	fmt.Println()

	return nil
}

// buildBanner is shown at the top of the help output.
func buildBanner() string {
	hex := lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true).Render("⬡")
	name := lipgloss.NewStyle().Foreground(lipgloss.Color("#F1F5F9")).Bold(true).Render("NetProbe")
	tag := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")).Render("Speed with Intelligence — by Muhammad Shawon")
	return fmt.Sprintf("\n  %s %s\n  %s", hex, name, tag)
}
