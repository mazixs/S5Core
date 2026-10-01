package tcptune

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Not in golang.org/x/sys yet.
const tcpRTOMinUS = 45 // TCP_RTO_MIN_US

type option struct {
	name  string
	opt   int
	value int
}

// Thin linear timeouts and a 20 ms timer floor. The cap of the timer
// (TCP_RTO_MAX_MS) and TCP_USER_TIMEOUT are left alone on purpose: from them
// the kernel derives when a connection that keeps retransmitting is closed
// (docs/benchmarks/game-tuning.md, "Обрывы и потолок таймера").
var options = []option{
	{"TCP_THIN_LINEAR_TIMEOUTS", unix.TCP_THIN_LINEAR_TIMEOUTS, 1},
	{"TCP_RTO_MIN_US", tcpRTOMinUS, 20_000},
}

func set(sc syscall.Conn) (Skipped, error) {
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	skipped := Skipped{}
	err = raw.Control(func(fd uintptr) {
		for _, o := range options {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, o.opt, o.value); err != nil {
				skipped[o.name] = err
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return skipped, nil
}
