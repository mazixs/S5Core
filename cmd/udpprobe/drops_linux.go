package main

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// udpSockets reads the drops column of /proc/net/udp and udp6 by socket
// inode: the one namespace count cannot say whether the proxy or the probe
// lost a burst.
func udpSockets() (map[string]socketDrops, error) {
	out := map[string]socketDrops{}
	for i, table := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(table)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines[min(1, len(lines)):] {
			f := strings.Fields(line)
			if len(f) < 13 {
				continue
			}
			drops, err := strconv.ParseUint(f[12], 10, 64)
			if err != nil {
				continue
			}
			out[f[9]] = socketDrops{Local: procAddr(f[1]), Drops: drops}
		}
	}
	return out, nil
}

// socketsThatDropped names the process behind each socket that dropped
// datagrams since before, where this user may see it.
func socketsThatDropped(before map[string]socketDrops) ([]socketDrops, error) {
	after, err := udpSockets()
	if err != nil {
		return nil, err
	}
	dropped := dropsSince(before, after)
	if len(dropped) > 0 {
		owners := socketOwners()
		for i := range dropped {
			dropped[i].Owner = owners[dropped[i].inode]
		}
	}
	return dropped, nil
}

// procAddr turns 0100007F:1F90 into 127.0.0.1:8080: the address is in 32-bit
// words of host order, the port in network order.
func procAddr(s string) string {
	host, port, ok := strings.Cut(s, ":")
	raw, err := hex.DecodeString(host)
	if !ok || err != nil || len(raw)%4 != 0 {
		return s
	}
	for w := 0; w < len(raw); w += 4 {
		binary.NativeEndian.PutUint32(raw[w:], binary.BigEndian.Uint32(raw[w:]))
	}
	p, err := strconv.ParseUint(port, 16, 16)
	addr, ok := netip.AddrFromSlice(raw)
	if err != nil || !ok {
		return s
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p)).String()
}

func socketOwners() map[string]string {
	owners := map[string]string{}
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range fds {
		link, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		pid := strings.Split(fd, "/")[2]
		comm, _ := os.ReadFile("/proc/" + pid + "/comm")
		owners[strings.TrimSuffix(link[len("socket:["):], "]")] = strings.TrimSpace(string(comm)) + "[" + pid + "]"
	}
	return owners
}
