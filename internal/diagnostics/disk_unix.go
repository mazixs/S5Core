//go:build unix

package diagnostics

import "golang.org/x/sys/unix"

func freeDisk(dir string) (uint64, error) {
	var s unix.Statfs_t
	err := unix.Statfs(dir, &s)
	return s.Bavail * uint64(s.Bsize), err
}
