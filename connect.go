//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func runConnect(ctx context.Context, ip net.IP, port int, timeout time.Duration, lg *eventLog) string {
	v4 := ip.To4() != nil
	domain := unix.AF_INET
	if !v4 {
		domain = unix.AF_INET6
	}

	fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		lg.addf("connect", "socket() failed: %v", err)
		return fmt.Sprintf("socket: %v", err)
	}
	defer unix.Close(fd)

	// Subscribe to ICMP errors delivered to this socket's error queue.
	if v4 {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	} else {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	}

	var sa unix.Sockaddr
	if v4 {
		a := &unix.SockaddrInet4{Port: port}
		copy(a.Addr[:], ip.To4())
		sa = a
	} else {
		a := &unix.SockaddrInet6{Port: port}
		copy(a.Addr[:], ip.To16())
		sa = a
	}

	lg.addf("connect", "socket fd=%d domain=%s", fd, domainName(domain))
	start := time.Now()
	err = unix.Connect(fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		lg.addf("connect", "connect() immediate error: %v", err)
		return err.Error()
	}
	lg.addf("connect", "connect() -> EINPROGRESS (nonblocking)")

	if ln, gerr := unix.Getsockname(fd); gerr == nil {
		lg.addf("connect", "bound locally to %s", sockaddrString(ln))
	}

	deadline := start.Add(timeout)
	var lastInfo *unix.TCPInfo
	for {
		if ctx.Err() != nil {
			return "canceled"
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			logTCPInfo(fd, lg, "final", lastInfo)
			drainErrorQueue(fd, lg)
			return fmt.Sprintf("TIMEOUT after %s (no SYN-ACK and no terminal error)", timeout)
		}
		pollMs := int(remaining.Milliseconds())
		if pollMs > 1000 {
			pollMs = 1000
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT | unix.POLLERR}}
		n, perr := unix.Poll(fds, pollMs)
		if perr != nil {
			if perr == unix.EINTR {
				continue
			}
			return fmt.Sprintf("poll: %v", perr)
		}
		drainErrorQueue(fd, lg)
		if n == 0 {
			if info := logTCPInfo(fd, lg, "progress", lastInfo); info != nil {
				lastInfo = info
			}
			continue
		}
		if fds[0].Revents&(unix.POLLOUT|unix.POLLERR) == 0 {
			continue
		}
		soErr, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		elapsed := time.Since(start).Seconds()
		if gerr != nil {
			return fmt.Sprintf("getsockopt(SO_ERROR): %v", gerr)
		}
		if soErr == 0 {
			lg.addf("connect", "ESTABLISHED in %.3fs", elapsed)
			logTCPInfo(fd, lg, "final", lastInfo)
			return "SUCCESS"
		}
		e := unix.Errno(soErr)
		lg.addf("connect", "SO_ERROR=%v after %.3fs", e, elapsed)
		logTCPInfo(fd, lg, "final", lastInfo)
		return e.Error()
	}
}

func domainName(d int) string {
	switch d {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	}
	return fmt.Sprintf("AF_%d", d)
}

func sockaddrString(sa unix.Sockaddr) string {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	case *unix.SockaddrInet6:
		return fmt.Sprintf("[%s]:%d", net.IP(a.Addr[:]).String(), a.Port)
	}
	return fmt.Sprintf("%T", sa)
}

func logTCPInfo(fd int, lg *eventLog, label string, last *unix.TCPInfo) *unix.TCPInfo {
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil || info == nil {
		return nil
	}
	// Skip duplicate progress lines.
	if label == "progress" && last != nil &&
		last.State == info.State &&
		last.Retransmits == info.Retransmits &&
		last.Total_retrans == info.Total_retrans {
		return info
	}
	lg.addf("tcp_info", "%s: state=%s retransmits=%d total_retrans=%d unacked=%d rtt=%dus rto=%dus",
		label,
		tcpStateName(info.State),
		info.Retransmits,
		info.Total_retrans,
		info.Unacked,
		info.Rtt,
		info.Rto,
	)
	return info
}

func tcpStateName(s uint8) string {
	// From linux/include/net/tcp_states.h
	switch s {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	}
	return fmt.Sprintf("STATE_%d", s)
}

// sock_extended_err, from include/uapi/linux/errqueue.h
type sockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}

func parseSockExtendedErr(b []byte) (sockExtendedErr, bool) {
	if len(b) < 16 {
		return sockExtendedErr{}, false
	}
	return sockExtendedErr{
		Errno:  binary.LittleEndian.Uint32(b[0:4]),
		Origin: b[4],
		Type:   b[5],
		Code:   b[6],
		Pad:    b[7],
		Info:   binary.LittleEndian.Uint32(b[8:12]),
		Data:   binary.LittleEndian.Uint32(b[12:16]),
	}, true
}

func eeOriginName(o uint8) string {
	switch o {
	case 0:
		return "NONE"
	case 1:
		return "LOCAL"
	case 2:
		return "ICMP"
	case 3:
		return "ICMP6"
	case 4:
		return "TXSTATUS"
	}
	return fmt.Sprintf("%d", o)
}

func icmpDescription(origin, t, c uint8) string {
	if origin != 2 && origin != 3 {
		return ""
	}
	switch t {
	case 3: // v4 destination unreachable (also matches some v6 codes)
		v4codes := map[uint8]string{
			0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable",
			3: "port unreachable", 4: "fragmentation needed (PMTU)",
			5: "source route failed", 6: "destination network unknown",
			7: "destination host unknown", 9: "dest network admin prohibited",
			10: "dest host admin prohibited", 13: "communication admin prohibited",
		}
		if origin == 2 {
			if s, ok := v4codes[c]; ok {
				return "dest-unreach: " + s
			}
			return fmt.Sprintf("dest-unreach code=%d", c)
		}
	case 1: // v6 destination unreachable
		if origin == 3 {
			v6codes := map[uint8]string{
				0: "no route", 1: "admin prohibited", 3: "address unreachable",
				4: "port unreachable", 5: "source address failed policy",
			}
			if s, ok := v6codes[c]; ok {
				return "dest-unreach: " + s
			}
			return fmt.Sprintf("dest-unreach code=%d", c)
		}
	case 11:
		return "time-exceeded (TTL expired)"
	case 12:
		return "parameter-problem"
	}
	return fmt.Sprintf("type=%d code=%d", t, c)
}

func drainErrorQueue(fd int, lg *eventLog) {
	buf := make([]byte, 1500)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, from, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return
		}
		var fromStr string
		switch a := from.(type) {
		case *unix.SockaddrInet4:
			fromStr = fmt.Sprintf("%d.%d.%d.%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3])
		case *unix.SockaddrInet6:
			fromStr = net.IP(a.Addr[:]).String()
		default:
			fromStr = "?"
		}
		cmsgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr != nil {
			lg.addf("icmp", "errqueue from=%s bytes=%d (cmsg parse: %v)", fromStr, n, perr)
			continue
		}
		described := false
		for _, c := range cmsgs {
			if (c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_RECVERR) ||
				(c.Header.Level == unix.IPPROTO_IPV6 && c.Header.Type == unix.IPV6_RECVERR) {
				ee, ok := parseSockExtendedErr(c.Data)
				if !ok {
					continue
				}
				desc := icmpDescription(ee.Origin, ee.Type, ee.Code)
				lg.addf("icmp", "from=%s origin=%s errno=%v %s",
					fromStr, eeOriginName(ee.Origin), unix.Errno(ee.Errno), desc)
				described = true
			}
		}
		if !described {
			lg.addf("icmp", "errqueue from=%s bytes=%d (no SO_EE cmsg)", fromStr, n)
		}
	}
}
