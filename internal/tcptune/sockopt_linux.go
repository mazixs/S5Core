//go:build linux && !386 && !s390x

package tcptune

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// getsockopt is getsockopt(2) into memory of the caller's, with the length
// the kernel wrote left in *n. golang.org/x/sys/unix keeps its own
// unexported; this is the same call it makes on these architectures.
func getsockopt(fd uintptr, level, opt int, val unsafe.Pointer, n *uint32) error {
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(opt), uintptr(val), uintptr(unsafe.Pointer(n)), 0)
	if e != 0 {
		return e
	}
	return nil
}
