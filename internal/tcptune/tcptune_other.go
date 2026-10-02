//go:build !linux && !windows

package tcptune

import (
	"syscall"
	"time"
)

func set(syscall.Conn) (Skipped, error) { return nil, errUnsupported }

func setDeadAfter(syscall.Conn, time.Duration) error { return errUnsupported }
