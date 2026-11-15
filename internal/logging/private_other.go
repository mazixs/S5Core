//go:build !windows

package logging

import "os"

func openLogFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|noFollow, mode)
}

// An existing file keeps the mode its owner gave it.
func protectLogFile(string, os.FileMode) error { return nil }
