package veil

import (
	"crypto/rand"
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
		pad, err := OpeningPad(psk, randomSecret(t), ctx, limit)
		if err != nil {
			t.Fatalf("OpeningPad: %v", err)
		}
		if pad < 0 || pad > limit {
			t.Fatalf("pad %d is outside [0, %d]", pad, limit)
		}
		seen[pad]++
	}

	// Every value in the range should turn up in 400 draws over 21 values; the
	// expected count is 19, so an absent one is a bug, not bad luck.
	if len(seen) != limit+1 {
		t.Fatalf("pads took %d of %d possible values in %d connections: %v",
			len(seen), limit+1, runs, seen)
	}
}

// A different PSK or a different context has to give a different pad for the
// same secret: the pad is derived through the same labels as the keys, and a
// pad that survived a context change would mean the label is not in the
// derivation at all.
func TestTheOpeningPadFollowsThePSKAndTheContext(t *testing.T) {
	secret := randomSecret(t)
	base, err := OpeningPad(testPSK(), secret, Context{Version: "v1"}, 20)
	if err != nil {
		t.Fatalf("OpeningPad: %v", err)
	}

	differs := 0
	other := []struct {
		name string
		psk  []byte
		ctx  Context
	}{
		{"another psk", randomSecret(t), Context{Version: "v1"}},
		{"another version", testPSK(), Context{Version: "v2"}},
		{"another node", testPSK(), Context{Version: "v1", NodeID: "edge"}},
		{"another cipher", testPSK(), Context{Version: "v1", Cipher: CipherChaCha}},
	}
	for _, o := range other {
		pad, err := OpeningPad(o.psk, secret, o.ctx, 20)
		if err != nil {
			t.Fatalf("%s: OpeningPad: %v", o.name, err)
		}
		if pad != base {
			differs++
		}
	}
	// Each one differs with probability 20/21, so all four matching would be a
	// one-in-200000 accident - but any single collision is ordinary. Requiring
	// most of them to differ tests the derivation without being flaky.
	if differs < len(other)-1 {
		t.Fatalf("%d of %d context changes left the pad at %d", len(other)-differs, len(other), base)
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
