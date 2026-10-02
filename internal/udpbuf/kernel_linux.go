package udpbuf

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// grow asks for Want. SO_RCVBUFFORCE passes net.core.rmem_max for a process
// with CAP_NET_ADMIN; without it the kernel refuses, and SO_RCVBUF takes what
// rmem_max allows. The size is read back, because neither says what it gave.
func grow(c *net.UDPConn) (Got, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return Got{}, err
	}
	var got int
	var setErr, getErr error
	if err := rc.Control(func(fd uintptr) {
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, Want) != nil {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, Want)
		}
		got, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return Got{}, err
	}
	if getErr != nil {
		return Got{}, errors.Join(setErr, getErr)
	}
	return Got{Bytes: got, Full: got >= 2*Want}, setErr
}

func limit() int {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// ReceiveDrops is how many datagrams the kernel dropped for a full receive
// buffer, IPv4 and IPv6 together. The count belongs to the network
// namespace, not to the process: in a container it is the server's alone, on
// a host it takes in every UDP socket there. ok is false where the kernel does
// not say; a host without IPv6 has only the IPv4 count.
func ReceiveDrops() (n uint64, ok bool) {
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, false
	}
	if n, ok = parseSNMP(string(b)); !ok {
		return 0, false
	}
	if b, err := os.ReadFile("/proc/net/snmp6"); err == nil {
		if v6, ok := parseSNMP6(string(b)); ok {
			n += v6
		}
	}
	return n, true
}

// parseSNMP reads RcvbufErrors of the Udp table in /proc/net/snmp, which is
// a line of names followed by a line of values.
func parseSNMP(b string) (uint64, bool) {
	var names []string
	for _, line := range strings.Split(b, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		for i, name := range names {
			if name == "RcvbufErrors" && i+1 < len(f) {
				v, err := strconv.ParseUint(f[i+1], 10, 64)
				return v, err == nil
			}
		}
		return 0, false
	}
	return 0, false
}

// parseSNMP6 reads Udp6RcvbufErrors of /proc/net/snmp6, a name and a value
// per line.
func parseSNMP6(b string) (uint64, bool) {
	for _, line := range strings.Split(b, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Udp6RcvbufErrors" {
			v, err := strconv.ParseUint(f[1], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}
