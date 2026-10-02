package tcptune

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func infoOf(sc syscall.Conn) (Info, bool) {
	raw, err := sc.SyscallConn()
	if err != nil {
		return Info{}, false
	}
	var ti *unix.TCPInfo
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		ti, gerr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || gerr != nil {
		return Info{}, false
	}
	return Info{
		RTT:         time.Duration(ti.Rtt) * time.Microsecond,
		Unacked:     ti.Unacked,
		Retransmits: ti.Retransmits,
		SinceData:   time.Duration(ti.Last_data_recv) * time.Millisecond,
		SinceAck:    time.Duration(ti.Last_ack_recv) * time.Millisecond,
	}, true
}
