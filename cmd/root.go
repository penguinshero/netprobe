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

var (
	iface    string
	cidr     string
	fallback bool
)

var root = &cobra.Command{
	Use:           "netprobe",
	Short:         "Speed with Intelligence — by Muhammad Shawon",
	Long:          buildBanner(),
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
	root.Flags().BoolVarP(&fallback, "fallback", "f", false, "Also probe via TCP when a host doesn't respond to ICMP")
}

func run(cmd *cobra.Command, args []string) error {
	if iface == "" && cidr == "" {
		return cmd.Help()
	}

	ui.PrintHeader()

	var target string

	if cidr != "" {
		target = cidr
	} else {
		subnet, err := network.SubnetFromInterface(iface)
		if err != nil {
			return fmt.Errorf("could not resolve interface %q: %w", iface, err)
		}
		target = subnet
	}

	ui.PrintTarget(iface, target)

	hosts, err := scanner.DiscoverHosts(target, fallback)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	ui.PrintResults(hosts, fallback)
	return nil
}

// buildBanner is shown when the user runs netprobe -h.
func buildBanner() string {
	hex := lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true).Render("⬡")
	name := lipgloss.NewStyle().Foreground(lipgloss.Color("#F1F5F9")).Bold(true).Render("NetProbe")
	tag := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")).Render("Speed with Intelligence — by Muhammad Shawon")
	return fmt.Sprintf("\n  %s %s\n  %s", hex, name, tag)
}
