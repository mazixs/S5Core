package tcptune

import (
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func set(syscall.Conn) (Skipped, error) { return nil, errUnsupported }

// TCP_MAXRTMS: how long Windows retransmits one segment before it aborts the
// connection.
func setDeadAfter(sc syscall.Conn, d time.Duration) error {
	return control(sc, func(fd uintptr) error {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_MAXRTMS, int(d.Milliseconds()))
	})
}
