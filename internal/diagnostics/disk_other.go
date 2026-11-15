//go:build !unix && !windows

package diagnostics

import "errors"

func freeDisk(string) (uint64, error) { return 0, errors.New("free-space query unsupported") }
