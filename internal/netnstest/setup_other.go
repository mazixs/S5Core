//go:build !linux

package netnstest

import "errors"

func setUp() error { return errors.New("network namespaces are Linux only") }
