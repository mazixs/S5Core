package tcptune

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fastOpenQueue bounds the connections whose SYN data was accepted and that
// have not finished the handshake yet; past it the kernel falls back to an
// ordinary handshake.
const fastOpenQueue = 256

// TCPI_OPT_SYN_DATA, not in golang.org/x/sys.
const tcpiOptSYNData = 0x20

// TCP_SYN_SENT of include/net/tcp_states.h, the state of tcpi_state.
const tcpSynSent = 2

func setListenFastOpen(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, fastOpenQueue)
}

func setConnectFastOpen(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
}

func tcpInfo(sc syscall.Conn) (*unix.TCPInfo, bool) {
	var ti *unix.TCPInfo
	err := control(sc, func(fd uintptr) error {
		var err error
		ti, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		return err
	})
	return ti, err == nil
}

func synData(sc syscall.Conn) (bool, bool) {
	ti, ok := tcpInfo(sc)
	if !ok {
		return false, false
	}
	return ti.Options&tcpiOptSYNData != 0, true
}

func synSent(sc syscall.Conn) (bool, bool) {
	ti, ok := tcpInfo(sc)
	if !ok {
		return false, false
	}
	return ti.State == tcpSynSent, true
}

func fastOpenClientFail(sc syscall.Conn) (int, bool) {
	ti, ok := tcpInfo(sc)
	if !ok {
		return FastOpenFailUnknown, false
	}
	return clientFail((*[unix.SizeofTCPInfo]byte)(unsafe.Pointer(ti))[7], littleEndian), true
}

var littleEndian = binary.NativeEndian.Uint16([]byte{1, 0}) == 1

// clientFail reads tcpi_fastopen_client_fail:2 from the byte after
// tcpi_options, which it shares with tcpi_delivery_rate_app_limited:1 and
// which x/sys keeps as padding. Bit fields are laid from the low bit on a
// little-endian machine and from the high bit on a big-endian one (mips).
func clientFail(b byte, little bool) int {
	if little {
		return int(b>>1) & 3
	}
	return int(b>>5) & 3
}

func dialsFastOpen(sc syscall.Conn) (bool, bool) {
	var v int
	err := control(sc, func(fd uintptr) error {
		var err error
		v, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
		return err
	})
	return v != 0, err == nil
}

// ProbeFastOpenConnect asks the kernel for TCP_FASTOPEN_CONNECT on a socket
// that is never connected: a kernel older than 4.11 refuses it.
func ProbeFastOpenConnect() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return setConnectFastOpen(uintptr(fd))
}

// FastOpenMode is net.ipv4.tcp_fastopen of the process's network namespace.
func FastOpenMode() (int, bool) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fastopen")
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return n, err == nil
}

// FastOpenPassive is how many connections the kernel accepted with data in
// the SYN, TCPFastOpenPassive of /proc/net/netstat. The count belongs to the
// network namespace, like ReceiveDrops of internal/udpbuf.
func FastOpenPassive() (uint64, bool) {
	b, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		return 0, false
	}
	return parseNetstat(string(b), "TcpExt:", "TCPFastOpenPassive")
}

// parseNetstat reads one counter of /proc/net/netstat, where each table is a
// line of names followed by a line of values.
func parseNetstat(b, table, name string) (uint64, bool) {
	var names []string
	for _, line := range strings.Split(b, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != table {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		for i, n := range names {
			if n == name && i+1 < len(f) {
				v, err := strconv.ParseUint(f[i+1], 10, 64)
				return v, err == nil
			}
		}
		return 0, false
	}
	return 0, false
}
