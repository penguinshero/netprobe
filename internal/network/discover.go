package network

import (
	"fmt"
	"net"
)

// SubnetFromInterface returns the IPv4 network for the given interface
// in CIDR notation, e.g. "192.168.1.0/24".
func SubnetFromInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface not found: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("could not read addresses: %w", err)
	}

	for _, addr := range addrs {
		var ip net.IP
		var mask net.IPMask

		switch v := addr.(type) {
		case *net.IPNet:
			ip, mask = v.IP, v.Mask
		case *net.IPAddr:
			ip = v.IP
			mask = ip.DefaultMask()
		}

		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}

		network := ip.Mask(mask)
		ones, _ := mask.Size()
		return fmt.Sprintf("%s/%d", network.String(), ones), nil
	}

	return "", fmt.Errorf("no usable IPv4 address on %q", name)
}

// ExpandHosts returns every usable host address in a CIDR range,
// skipping the network address and the broadcast address.
func ExpandHosts(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var hosts []string
	for cur := ip.Mask(ipNet.Mask); ipNet.Contains(cur); inc(cur) {
		clone := make(net.IP, len(cur))
		copy(clone, cur)
		if isEdge(clone, ipNet) {
			continue
		}
		hosts = append(hosts, clone.String())
	}

	return hosts, nil
}

// inc bumps an IP by one in-place.
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// isEdge reports whether ip is the network or broadcast address of the subnet.
func isEdge(ip net.IP, network *net.IPNet) bool {
	networkAddr := ip.Mask(network.Mask)
	if ip.Equal(networkAddr) {
		return true
	}
	broadcast := make(net.IP, len(networkAddr))
	for i := range networkAddr {
		broadcast[i] = networkAddr[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
