//go:build !windows

package privatefs

import "os"

// CreateTemp is os.CreateTemp, whose file is 0600 already.
func CreateTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

// MkdirAll is os.MkdirAll with 0700; an existing directory keeps its mode.
func MkdirAll(path string) error {
	return os.MkdirAll(path, 0o700)
}
