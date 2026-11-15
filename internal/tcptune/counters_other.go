//go:build !linux && !windows

package tcptune

import "syscall"

func countersOf(syscall.Conn) (Counters, error) { return Counters{}, errUnsupported }
