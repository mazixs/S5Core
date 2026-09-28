//go:build !linux

package main

import "errors"

var errNoSocketDrops = errors.New("per-socket drops are read on Linux only")

func udpSockets() (map[string]socketDrops, error) {
	return nil, errNoSocketDrops
}

func socketsThatDropped(map[string]socketDrops) ([]socketDrops, error) {
	return nil, errNoSocketDrops
}
