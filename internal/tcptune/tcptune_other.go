//go:build !linux

package tcptune

import "errors"

var errNotLinux = errors.New("tcptune: only Linux has these options")

func apply(_ uintptr, skipped Skipped) {
	skipped["TCP_THIN_LINEAR_TIMEOUTS"] = errNotLinux
}
