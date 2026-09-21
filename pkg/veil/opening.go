package veil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// OpeningPad is how many bytes of cover a client adds after its prologue on
// the wire, derived from the same secret the session keys come from.
//
// It exists because of what an encoded prologue costs elsewhere. A prologue
// that is printable on the wire (see the obfs package) buys an exemption from
// the level 1 rule, but a fixed-length printable opening is itself a shape: a
// classifier that learns "exactly 43 printable bytes, then binary" has a
// signature that needs no cryptanalysis. Drawing the length from the secret
// removes the constant without adding a field - the server derives the same
// number, and an observer without the PSK sees the boundary move between
// connections.
//
// The limit is the largest pad the caller will emit; the result is uniform
// enough over 0..limit for that purpose and identical on both ends. A limit of
// zero means no pad, which is what the raw encoding uses.
func OpeningPad(psk, secret []byte, ctx Context, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	prk, err := hkdf.Extract(sha256.New, psk, secret)
	if err != nil {
		return 0, fmt.Errorf("veil: opening pad derivation failed: %w", err)
	}
	out, err := hkdf.Expand(sha256.New, prk, ctx.normalized().label("client", "opening"), 2)
	if err != nil {
		return 0, fmt.Errorf("veil: opening pad derivation failed: %w", err)
	}
	return int(binary.BigEndian.Uint16(out)) % (limit + 1), nil
}
