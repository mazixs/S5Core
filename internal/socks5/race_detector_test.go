//go:build race

package socks5

func init() { raceDetector = true }
