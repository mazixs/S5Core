package veil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// LogIDSize is the length of a connection's log id: 48 bits, enough to find
// one connection among a day of them by time and account.
const LogIDSize = 6

// LogID names a connection in the logs of both ends. It comes from the session
// secret under a label of its own, so it is the same on the client and the
// server, says nothing of the keys, and costs nothing on the wire. Without the
// PSK it cannot be computed from a recorded prologue, which is what keeps a log
// line from being matched to captured traffic.
func LogID(psk, secret []byte, ctx Context) ([LogIDSize]byte, error) {
	var id [LogIDSize]byte
	if len(psk) != 32 || len(secret) == 0 {
		return id, fmt.Errorf("veil: log id needs the PSK and a session secret")
	}
	prk, err := hkdf.Extract(sha256.New, psk, secret)
	if err != nil {
		return id, fmt.Errorf("veil: log id derivation failed: %w", err)
	}
	out, err := hkdf.Expand(sha256.New, prk, ctx.normalized().label("both", "log-id"), LogIDSize)
	if err != nil {
		return id, fmt.Errorf("veil: log id derivation failed: %w", err)
	}
	copy(id[:], out)
	return id, nil
}
