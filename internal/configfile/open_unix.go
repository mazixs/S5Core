//go:build unix

package configfile

import (
	"golang.org/x/sys/unix"
	"os"
)

func open(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
