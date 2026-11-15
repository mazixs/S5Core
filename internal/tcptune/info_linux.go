package tcptune

import (
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A kernel fills as much of struct tcp_info as it knows and says how much.
// These are the lengths that hold the fields Info reads.
const (
	// infoBaseLen ends at tcpi_rtt, the last of the fields every kernel has.
	infoBaseLen = uint32(unsafe.Offsetof(unix.TCPInfo{}.Rtt) + unsafe.Sizeof(unix.TCPInfo{}.Rtt))
	// infoBytesAckedLen ends at tcpi_bytes_acked, added in Linux 4.1.
	infoBytesAckedLen = uint32(unsafe.Offsetof(unix.TCPInfo{}.Bytes_acked) + unsafe.Sizeof(unix.TCPInfo{}.Bytes_acked))
)

func infoOf(sc syscall.Conn) (Info, bool) {
	var ti unix.TCPInfo
	n, ok := readTCPInfo(sc, &ti)
	if !ok {
		return Info{}, false
	}
	return decodeInfo(&ti, n)
}

// decodeInfo reads ti as far as the n bytes the kernel wrote into it.
func decodeInfo(ti *unix.TCPInfo, n uint32) (Info, bool) {
	if n < infoBaseLen {
		return Info{}, false
	}
	info := Info{
		RTT:         time.Duration(ti.Rtt) * time.Microsecond,
		Unacked:     ti.Unacked,
		Retransmits: ti.Retransmits,
		SinceData:   time.Duration(ti.Last_data_recv) * time.Millisecond,
		SinceAck:    time.Duration(ti.Last_ack_recv) * time.Millisecond,
		State:       ti.State,
	}
	if n >= infoBytesAckedLen {
		info.BytesAcked, info.BytesAckedKnown = ti.Bytes_acked, true
	}
	return info, true
}

// readTCPInfo has the kernel fill ti and returns how many bytes it wrote.
// A *net.TCPConn is asked through its concrete SyscallConn: the compiler
// then sees the Control it calls, and the closure and ti stay on the stack.
func readTCPInfo(sc syscall.Conn, ti *unix.TCPInfo) (uint32, bool) {
	tc, ok := sc.(*net.TCPConn)
	if !ok {
		v, n, ok := readTCPInfoAny(sc)
		*ti = v
		return n, ok
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	n := uint32(unsafe.Sizeof(*ti))
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		gerr = getsockopt(fd, unix.IPPROTO_TCP, unix.TCP_INFO, unsafe.Pointer(ti), &n)
	}); err != nil || gerr != nil {
		return 0, false
	}
	return n, true
}

// readTCPInfoAny is readTCPInfo for any other socket. Its buffer escapes
// with the closure, so it is its own and copied out.
func readTCPInfoAny(sc syscall.Conn) (unix.TCPInfo, uint32, bool) {
	var ti unix.TCPInfo
	n := uint32(unsafe.Sizeof(ti))
	err := control(sc, func(fd uintptr) error {
		return getsockopt(fd, unix.IPPROTO_TCP, unix.TCP_INFO, unsafe.Pointer(&ti), &n)
	})
	return ti, n, err == nil
}
