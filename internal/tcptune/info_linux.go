package tcptune

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A kernel fills as much of struct tcp_info as it knows and says how much.
// infoBaseLen ends at tcpi_rtt, the last of the fields every kernel has.
const infoBaseLen = uint32(unsafe.Offsetof(unix.TCPInfo{}.Rtt) + unsafe.Sizeof(unix.TCPInfo{}.Rtt))

func infoOf(sc syscall.Conn) (Info, bool) {
	var ti unix.TCPInfo
	n, err := readTCPInfo(sc, &ti)
	if err != nil {
		return Info{}, false
	}
	return decodeInfo(&ti, n)
}

// decodeInfo reads ti as far as the n bytes the kernel wrote into it: the
// part of decodeCounters that Info has.
func decodeInfo(ti *unix.TCPInfo, n uint32) (Info, bool) {
	c, ok := decodeCounters(ti, n)
	if !ok {
		return Info{}, false
	}
	return Info{
		RTT:             c.RTT,
		Unacked:         c.Unacked,
		Retransmits:     c.Retransmits,
		SinceData:       c.SinceData,
		SinceAck:        c.SinceAck,
		State:           c.State,
		BytesAcked:      c.BytesAcked,
		BytesAckedKnown: c.Known(CounterBytesAcked),
	}, true
}

// readTCPInfo has the kernel fill ti and returns how many bytes it wrote.
// A *net.TCPConn is asked through its concrete SyscallConn: the compiler
// then sees the Control it calls, and the closure and ti stay on the stack.
func readTCPInfo(sc syscall.Conn, ti *unix.TCPInfo) (uint32, error) {
	tc, ok := sc.(*net.TCPConn)
	if !ok {
		v, n, err := readTCPInfoAny(sc)
		*ti = v
		return n, err
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, err
	}
	n := uint32(unsafe.Sizeof(*ti))
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		gerr = getsockopt(fd, unix.IPPROTO_TCP, unix.TCP_INFO, unsafe.Pointer(ti), &n)
	}); err != nil {
		return 0, err
	}
	return n, gerr
}

// readTCPInfoAny is readTCPInfo for any other socket. Its buffer escapes
// with the closure, so it is its own and copied out.
func readTCPInfoAny(sc syscall.Conn) (unix.TCPInfo, uint32, error) {
	var ti unix.TCPInfo
	n := uint32(unsafe.Sizeof(ti))
	err := control(sc, func(fd uintptr) error {
		return getsockopt(fd, unix.IPPROTO_TCP, unix.TCP_INFO, unsafe.Pointer(&ti), &n)
	})
	return ti, n, err
}
