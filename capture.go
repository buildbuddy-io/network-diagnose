//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

func runCapture(ctx context.Context, ifname string, targetIP net.IP, targetPort int, lg *eventLog, ready chan<- struct{}) error {
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifname),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(8),
		afpacket.OptPollTimeout(50*time.Millisecond),
	)
	if err != nil {
		close(ready)
		return fmt.Errorf("AF_PACKET open %s: %w", ifname, err)
	}
	defer h.Close()
	lg.addf("capture", "AF_PACKET listening on %s", ifname)
	close(ready)

	for {
		if ctx.Err() != nil {
			break
		}
		data, _, err := h.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			return err
		}
		describePacket(data, targetIP, targetPort, lg)
	}

	// Drain packets still in the ring buffer after cancellation so we don't
	// miss the tail of the handshake (SYN-ACK / ACK) or trailing ICMP.
	drainDeadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(drainDeadline) {
		data, _, err := h.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				return nil
			}
			return err
		}
		describePacket(data, targetIP, targetPort, lg)
	}
	return nil
}

func describePacket(data []byte, targetIP net.IP, targetPort int, lg *eventLog) {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	var srcIP, dstIP net.IP
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	} else if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	} else {
		return
	}

	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		isOut := dstIP.Equal(targetIP) && int(t.DstPort) == targetPort
		isIn := srcIP.Equal(targetIP) && int(t.SrcPort) == targetPort
		if !isOut && !isIn {
			return
		}
		arrow := "<-"
		if isOut {
			arrow = "->"
		}
		lg.addf("pkt", "%s TCP %s:%d %s %s:%d [%s] seq=%d ack=%d win=%d len=%d",
			arrow, srcIP, t.SrcPort, arrow, dstIP, t.DstPort,
			tcpFlagString(t), t.Seq, t.Ack, t.Window, len(t.Payload))
		return
	}

	if icmp := pkt.Layer(layers.LayerTypeICMPv4); icmp != nil {
		ic := icmp.(*layers.ICMPv4)
		payload := ic.Payload
		if len(payload) >= 20 {
			inner := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{NoCopy: true})
			if oip := inner.Layer(layers.LayerTypeIPv4); oip != nil {
				o := oip.(*layers.IPv4)
				if !o.DstIP.Equal(targetIP) {
					return
				}
				extra := ""
				if itcp := inner.Layer(layers.LayerTypeTCP); itcp != nil {
					it := itcp.(*layers.TCP)
					extra = fmt.Sprintf(" tcp %d->%d", it.SrcPort, it.DstPort)
				}
				lg.addf("pkt", "ICMPv4 %s from %s (re: %s->%s proto=%d%s)",
					ic.TypeCode, srcIP, o.SrcIP, o.DstIP, o.Protocol, extra)
				return
			}
		}
		if srcIP.Equal(targetIP) || dstIP.Equal(targetIP) {
			lg.addf("pkt", "ICMPv4 %s src=%s dst=%s", ic.TypeCode, srcIP, dstIP)
		}
		return
	}

	if icmp := pkt.Layer(layers.LayerTypeICMPv6); icmp != nil {
		ic := icmp.(*layers.ICMPv6)
		if srcIP.Equal(targetIP) || dstIP.Equal(targetIP) {
			lg.addf("pkt", "ICMPv6 %s src=%s dst=%s", ic.TypeCode, srcIP, dstIP)
		}
	}
}

func tcpFlagString(t *layers.TCP) string {
	var s []byte
	if t.SYN {
		s = append(s, 'S')
	}
	if t.ACK {
		s = append(s, 'A')
	}
	if t.FIN {
		s = append(s, 'F')
	}
	if t.RST {
		s = append(s, 'R')
	}
	if t.PSH {
		s = append(s, 'P')
	}
	if t.URG {
		s = append(s, 'U')
	}
	if t.ECE {
		s = append(s, 'E')
	}
	if t.CWR {
		s = append(s, 'C')
	}
	if len(s) == 0 {
		return "-"
	}
	return string(s)
}
