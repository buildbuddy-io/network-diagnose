//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

var (
	targetFlag = flag.String("target", "", "target host:port, e.g. foo.buildbuddy.io:443")
	timeout    = flag.Duration("timeout", 30*time.Second, "per-attempt connect timeout")
	count      = flag.Int("count", 1, "number of attempts per resolved IP per iteration")
	interval   = flag.Duration("interval", 0, "if set, re-run continuously every interval until SIGINT")
	ifaceFlag  = flag.String("iface", "", "capture interface (default: auto-detect from route)")
	noCapture  = flag.Bool("no-capture", false, "disable AF_PACKET capture (no NET_RAW needed)")
	onlyV4     = flag.Bool("ipv4", false, "only use IPv4 addresses from DNS")
)

type event struct {
	t    time.Time
	src  string
	text string
}

type eventLog struct {
	mu     sync.Mutex
	start  time.Time
	events []event
}

func newLog() *eventLog { return &eventLog{start: time.Now()} }

func (l *eventLog) add(src, text string) {
	l.mu.Lock()
	l.events = append(l.events, event{t: time.Now(), src: src, text: text})
	l.mu.Unlock()
}

func (l *eventLog) addf(src, format string, args ...any) {
	l.add(src, fmt.Sprintf(format, args...))
}

func (l *eventLog) print() {
	l.mu.Lock()
	defer l.mu.Unlock()
	sort.SliceStable(l.events, func(i, j int) bool { return l.events[i].t.Before(l.events[j].t) })
	for _, e := range l.events {
		rel := e.t.Sub(l.start).Seconds()
		fmt.Printf("  T+%7.3fs  [%-8s] %s\n", rel, e.src, e.text)
	}
}

func main() {
	flag.Parse()
	if *targetFlag == "" {
		fmt.Fprintln(os.Stderr, "--target is required, e.g. --target=foo.buildbuddy.io:443")
		os.Exit(2)
	}
	host, portStr, err := net.SplitHostPort(*targetFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --target: %v\n", err)
		os.Exit(2)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("=== network-diagnose -> %s:%d ===\n\n", host, port)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	iter := 0
	for {
		iter++
		if *interval > 0 {
			fmt.Printf("### Iteration %d @ %s ###\n\n", iter, time.Now().Format(time.RFC3339))
		}

		fmt.Println("[DNS]")
		ips, err := resolveHost(host, *onlyV4)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DNS resolution failed: %v\n", err)
			if *interval == 0 {
				os.Exit(1)
			}
			ips = nil
		}
		if len(ips) == 0 && *interval == 0 {
			fmt.Fprintln(os.Stderr, "no usable IPs")
			os.Exit(1)
		}
		fmt.Println()

		for attempt := 1; attempt <= *count; attempt++ {
			for _, ip := range ips {
				if ctx.Err() != nil {
					return
				}
				fmt.Printf("[Attempt %d/%d -> %s:%d]\n", attempt, *count, ip, port)
				runAttempt(ctx, ip, port, *timeout, *ifaceFlag, !*noCapture)
				fmt.Println()
			}
		}

		if *interval == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}

func runAttempt(parent context.Context, ip net.IP, port int, to time.Duration, ifname string, wantCapture bool) {
	lg := newLog()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var wg sync.WaitGroup
	if wantCapture {
		if ifname == "" {
			detected, err := interfaceForIP(ip)
			if err != nil {
				lg.addf("setup", "interface detection failed: %v - continuing without capture", err)
				wantCapture = false
			} else {
				ifname = detected
				lg.addf("setup", "capture interface: %s", ifname)
			}
		}
	}
	if wantCapture {
		ready := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := runCapture(ctx, ifname, ip, port, lg, ready)
			if err != nil && !errors.Is(err, context.Canceled) {
				lg.addf("capture", "ERROR: %v", err)
			}
		}()
		select {
		case <-ready:
		case <-time.After(500 * time.Millisecond):
			lg.add("setup", "capture startup timed out; continuing anyway")
		}
	} else {
		lg.add("setup", "capture disabled (run with NET_RAW capability to enable)")
	}

	result := runConnect(ctx, ip, port, to, lg)
	// Let the capture pick up the last in-flight packets (SYN-ACK, our ACK,
	// or trailing ICMP after a timeout) before we tear it down.
	if wantCapture {
		time.Sleep(150 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	lg.print()
	fmt.Printf("  Result: %s\n", result)
}
