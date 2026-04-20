//go:build linux

package main

import (
	"fmt"
	"net"
)

// interfaceForIP asks the kernel to select a route to target via a connected
// UDP socket (no packets are sent), then finds the interface that owns the
// resulting local address.
func interfaceForIP(target net.IP) (string, error) {
	network := "udp4"
	if target.To4() == nil {
		network = "udp6"
	}
	c, err := net.Dial(network, net.JoinHostPort(target.String(), "9"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	localIP := c.LocalAddr().(*net.UDPAddr).IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(localIP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface matches source IP %s", localIP)
}
