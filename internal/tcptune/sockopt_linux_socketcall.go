//go:build linux && (386 || s390x)

package tcptune

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysGetsockopt is SYS_GETSOCKOPT of include/uapi/linux/net.h: the number of
// getsockopt among the socketcall(2) operations.
const sysGetsockopt = 15

// getsockopt is getsockopt(2) into memory of the caller's, with the length
// the kernel wrote left in *n. Here it goes through socketcall, as
// golang.org/x/sys/unix does on these architectures: kernels before 4.3 have
// no getsockopt system call of their own.
func getsockopt(fd uintptr, level, opt int, val unsafe.Pointer, n *uint32) error {
	args := [5]uintptr{fd, uintptr(level), uintptr(opt), uintptr(val), uintptr(unsafe.Pointer(n))}
	_, _, e := unix.Syscall(unix.SYS_SOCKETCALL, sysGetsockopt, uintptr(unsafe.Pointer(&args)), 0)
	if e != 0 {
		return e
	}
	return nil
}
