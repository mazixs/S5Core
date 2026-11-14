//go:build !windows

package socks5

import (
	"errors"
	"syscall"
)

func socketErrno(err error, code syscall.Errno) bool { return errors.Is(err, code) }
