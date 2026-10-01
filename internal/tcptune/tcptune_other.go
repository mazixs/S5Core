//go:build !linux

package tcptune

import "syscall"

func set(syscall.Conn) (Skipped, error) { return nil, errUnsupported }
