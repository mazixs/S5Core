package tcptune

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioTCPInfo is SIO_TCP_INFO; version 0 of its answer, TCP_INFO_v0, is
// there since Windows 10 1703 and needs no privilege.
const (
	sioTCPInfo   = windows.IOC_INOUT | windows.IOC_VENDOR | 39
	tcpInfoV0Len = 88
)

type tcpInfoV0 [tcpInfoV0Len]byte

func countersOf(sc syscall.Conn) (Counters, error) {
	var b tcpInfoV0
	n, err := readTCPInfoV0(sc, &b)
	if err != nil {
		return Counters{}, err
	}
	if n != tcpInfoV0Len {
		return Counters{}, errShortInfo
	}
	return decodeTCPInfoV0(&b), nil
}

// decodeTCPInfoV0 maps TCP_INFO_v0 onto the fields that mean the same as on
// Linux, and onto the ones of its own. Its state has another numbering and
// is left out.
func decodeTCPInfoV0(b *tcpInfoV0) Counters {
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
	u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }
	return Counters{
		Has: CounterRTT | CounterMinRTT | CounterInFlightBytes | CounterCongestionWindowBytes |
			CounterSendWindow | CounterReceiveWindow | CounterBytesSent | CounterBytesReceived |
			CounterBytesRetrans | CounterTimeoutEpisodes,
		RTT:                   time.Duration(u32(20)) * time.Microsecond,
		MinRTT:                time.Duration(u32(24)) * time.Microsecond,
		InFlightBytes:         u32(28),
		CongestionWindowBytes: u32(32),
		SendWindow:            u32(36),
		ReceiveWindow:         u32(40),
		BytesSent:             u64(48),
		BytesReceived:         u64(56),
		BytesRetrans:          uint64(u32(68)),
		TimeoutEpisodes:       u32(80),
	}
}

// readTCPInfoV0 asks for TCP_INFO_v0 and returns how many bytes came back.
// A *net.TCPConn is asked through its concrete SyscallConn, as on Linux, so
// nothing escapes.
func readTCPInfoV0(sc syscall.Conn, b *tcpInfoV0) (uint32, error) {
	tc, ok := sc.(*net.TCPConn)
	if !ok {
		v, n, err := readTCPInfoV0Any(sc)
		*b = v
		return n, err
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var version, n uint32
	var ierr error
	if err := raw.Control(func(fd uintptr) { ierr = askTCPInfoV0(fd, &version, b, &n) }); err != nil {
		return 0, err
	}
	return n, ierr
}

// readTCPInfoV0Any is readTCPInfoV0 for any other socket.
func readTCPInfoV0Any(sc syscall.Conn) (tcpInfoV0, uint32, error) {
	var b tcpInfoV0
	var version, n uint32
	err := control(sc, func(fd uintptr) error { return askTCPInfoV0(fd, &version, &b, &n) })
	return b, n, err
}

func askTCPInfoV0(fd uintptr, version *uint32, b *tcpInfoV0, n *uint32) error {
	return windows.WSAIoctl(windows.Handle(fd), sioTCPInfo, (*byte)(unsafe.Pointer(version)), 4, &b[0], tcpInfoV0Len, n, nil, 0)
}
