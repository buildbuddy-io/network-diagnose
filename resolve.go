//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

func resolveHost(host string, onlyV4 bool) ([]net.IP, error) {
	start := time.Now()
	if ip := net.ParseIP(host); ip != nil {
		fmt.Printf("  T+%7.3fs  %s is an IP literal\n", 0.0, host)
		if onlyV4 && ip.To4() == nil {
			return nil, fmt.Errorf("--ipv4 set but %s is IPv6", ip)
		}
		return []net.IP{ip}, nil
	}
	fmt.Printf("  T+%7.3fs  resolving %s (system resolver)\n", 0.0, host)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return nil, fmt.Errorf("after %.3fs: %w", elapsed, err)
	}
	var ips []net.IP
	for _, a := range addrs {
		kind := "A"
		if a.IP.To4() == nil {
			kind = "AAAA"
		}
		if onlyV4 && a.IP.To4() == nil {
			fmt.Printf("  T+%7.3fs  -> %s (%s, skipped)\n", elapsed, a.IP, kind)
			continue
		}
		fmt.Printf("  T+%7.3fs  -> %s (%s)\n", elapsed, a.IP, kind)
		ips = append(ips, a.IP)
	}
	return ips, nil
}
