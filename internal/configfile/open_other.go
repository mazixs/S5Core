//go:build !unix

package configfile

import (
	"errors"
	"os"
)

func open(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	return os.Open(path)
}
