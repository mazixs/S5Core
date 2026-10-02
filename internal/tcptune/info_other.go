//go:build !linux

package tcptune

import "syscall"

func infoOf(syscall.Conn) (Info, bool) { return Info{}, false }
