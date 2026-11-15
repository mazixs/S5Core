//go:build !unix && !windows

package privatefs

import (
	"errors"
	"os"
)

// CheckDir cannot tell who may reach a directory here.
func CheckDir(path string) error {
	return &os.PathError{Op: "checkdir", Path: path, Err: errors.ErrUnsupported}
}
