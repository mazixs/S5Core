package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// Plan task Ф5-6, the encoded opening. The pad length is what keeps a
// printable opening from being a constant of its own, so the properties it has
// to hold are: both ends derive the same number without a field on the wire,
// the number moves between connections, and it stays inside the range the
// encoder reserved for it. The wire format itself is checked in
// pkg/obfs/prologue_test.go; here only the derivation.

func randomSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestBothEndsDeriveTheSameOpeningPad(t *testing.T) {
	psk, secret, ctx := testPSK(), randomSecret(t), Context{Version: "v1"}

	client, err := OpeningPad(psk, secret, ctx, 20)
	if err != nil {
		t.Fatalf("OpeningPad: %v", err)
	}
	server, err := OpeningPad(psk, secret, ctx, 20)
	if err != nil {
		t.Fatalf("OpeningPad: %v", err)
	}
	if client != server {
		t.Fatalf("the two ends derived different pads: %d and %d", client, server)
	}
}

// The pad is the only thing hiding where the opening ends. A pad that came out
// the same for every connection would put the first frame back at a fixed
// offset, which is what the encoding was meant to remove.
func TestTheOpeningPadMovesWithTheSecret(t *testing.T) {
	const limit = 20
	psk, ctx := testPSK(), Context{Version: "v1"}

	seen := map[int]int{}
	const runs = 400
	for i := 0; i < runs; i++ {
		secret := make([]byte, 32)
		binary.LittleEndian.PutUint64(secret, uint64(i))
		pad, err := OpeningPad(psk, secret, ctx, limit)
		if err != nil {
			t.Fatalf("OpeningPad: %v", err)
		}
		if pad < 0 || pad > limit {
			t.Fatalf("pad %d is outside [0, %d]", pad, limit)
		}
		seen[pad]++
	}

	// This fixed corpus covers every output value. Unlike random draws it
	// cannot occasionally omit one merely by chance.
	if len(seen) != limit+1 {
		t.Fatalf("pads took %d of %d possible values in %d connections: %v",
			len(seen), limit+1, runs, seen)
	}
}

// Each PSK/context field must affect the pad derivation. Individual outputs
// may collide modulo 21, so compare a deterministic sequence for each field,
// rather than demanding that three of four random outputs differ.
func TestTheOpeningPadFollowsThePSKAndTheContext(t *testing.T) {
	other := []struct {
		name string
		psk  []byte
		ctx  Context
	}{
		{"another psk", bytes.Repeat([]byte{0xa5}, 32), Context{Version: "v1"}},
		{"another version", testPSK(), Context{Version: "v2"}},
		{"another node", testPSK(), Context{Version: "v1", NodeID: "edge"}},
		{"another cipher", testPSK(), Context{Version: "v1", Cipher: CipherChaCha}},
	}
	for _, o := range other {
		t.Run(o.name, func(t *testing.T) {
			differs := false
			for i := range 32 {
				secret := bytes.Repeat([]byte{byte(i)}, 32)
				base, err := OpeningPad(testPSK(), secret, Context{Version: "v1"}, 20)
				if err != nil {
					t.Fatal(err)
				}
				pad, err := OpeningPad(o.psk, secret, o.ctx, 20)
				if err != nil {
					t.Fatal(err)
				}
				differs = differs || pad != base
			}
			if !differs {
				t.Fatal("changing this field leaves the entire pad sequence unchanged")
			}
		})
	}
}

// The raw encoding asks for no pad at all, and a caller that passes a limit of
// zero must not get an error or a modulo by one.
func TestNoLimitMeansNoPad(t *testing.T) {
	for _, limit := range []int{0, -1} {
		pad, err := OpeningPad(testPSK(), randomSecret(t), Context{}, limit)
		if err != nil {
			t.Fatalf("limit %d: OpeningPad: %v", limit, err)
		}
		if pad != 0 {
			t.Fatalf("limit %d gave a pad of %d", limit, pad)
		}
	}
}
