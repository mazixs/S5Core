//go:build unix

package logging

import "syscall"

const noFollow = syscall.O_NOFOLLOW
