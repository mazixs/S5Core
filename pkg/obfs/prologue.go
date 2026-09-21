package obfs

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// PrologueEncoding is how a client's prologue appears on the wire.
//
// The prologue itself is 32 bytes of scheme output and is uniformly random by
// construction - which is exactly what the level 1 rule of the stealth
// checklist blocks. That rule drops a connection whose first packet looks
// fully encrypted unless it matches one of five exemptions, and measurement on
// a live path says the rule is real: a 256-byte random first packet was
// delivered in 20% of probes, while the same packet opening with 16 printable
// bytes was delivered in 98 probes out of 98 (docs/field/stealth.md).
//
// So the prologue goes out base64-encoded. Nothing else about the format
// changes: the frames after it are unchanged, the scheme does not know it
// happened, and the cost is eleven bytes plus a pad, once per connection.
type PrologueEncoding string

const (
	// ProloguePrintable encodes the prologue with base64 and follows it with
	// a pad of printable bytes whose length comes from the session secret.
	// The opening is then between 43 and 63 printable bytes, which exempts
	// the first packet under Ex4 (a printable run over twenty bytes) and
	// under Ex2 (the first six bytes printable) without claiming to be a
	// protocol the connection cannot then speak.
	ProloguePrintable PrologueEncoding = "printable"
	// PrologueRaw puts the scheme's bytes on the wire as they are. It is the
	// format of every build before this one, kept because a server accepts
	// both and a fleet is not updated in one step (docs/field/migration.md).
	PrologueRaw PrologueEncoding = "raw"
)

// DefaultPrologueEncoding is what a client uses when nothing says otherwise.
// It is the printable one: the raw encoding does not reach a server at all on
// a path that applies the rule, and a server understands both.
const DefaultPrologueEncoding = ProloguePrintable

// Valid reports whether this is an encoding the format defines. An unknown
// name is a configuration error and must be refused where it is set: taken
// as the default it would silently put a different format on the wire than
// the one the operator asked for.
func (e PrologueEncoding) Valid() bool {
	switch e {
	case "", ProloguePrintable, PrologueRaw:
		return true
	}
	return false
}

// prologueCoding is the alphabet on the wire. Standard base64 without
// padding: the '=' of a padded encoding would be a constant at a fixed
// offset, which is what level 2 of the checklist looks for.
var prologueCoding = base64.RawStdEncoding

// encodedPrologueSize is how many bytes the encoded prologue takes (43 for a
// 32-byte prologue), and openingPadMax is the largest pad after it.
const (
	encodedPrologueSize = (saltSize*8 + 5) / 6
	openingPadMax       = 20
	maxWirePrologue     = encodedPrologueSize + openingPadMax
)

// prologueAlphabet is the base64 alphabet, spelled out because the encoder
// does not expose single-character conversion and two places below need it.
const prologueAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// printableSet and prologueIndex are the alphabet as lookup tables. A server
// tells the two encodings apart by the first: a raw prologue is 32 uniformly
// random bytes and lands inside this 64-character set with probability 2^-64,
// so the test is a decision, not a heuristic.
var printableSet, prologueIndex = func() (set [256]bool, index [256]byte) {
	for i := 0; i < len(prologueAlphabet); i++ {
		set[prologueAlphabet[i]] = true
		index[prologueAlphabet[i]] = byte(i)
	}
	return set, index
}()

// looksEncoded reports whether these bytes can only be an encoded prologue.
func looksEncoded(b []byte) bool {
	for _, c := range b {
		if !printableSet[c] {
			return false
		}
	}
	return true
}

// encodeWirePrologue writes the encoded prologue and its pad into dst and
// returns how many bytes it used. dst must hold encodedPrologueSize+pad.
func encodeWirePrologue(dst, prologue []byte, pad int) (int, error) {
	if len(prologue) != saltSize {
		return 0, fmt.Errorf("obfs: prologue is %d bytes, the encoding carries %d", len(prologue), saltSize)
	}
	if pad < 0 || pad > openingPadMax {
		return 0, fmt.Errorf("obfs: opening pad of %d bytes is outside 0..%d", pad, openingPadMax)
	}
	if len(dst) < encodedPrologueSize+pad {
		return 0, fmt.Errorf("obfs: buffer of %d bytes cannot hold a %d-byte opening", len(dst), encodedPrologueSize+pad)
	}
	prologueCoding.Encode(dst, prologue)

	// 43 base64 characters carry 258 bits and the prologue is 256, so the
	// last character has two bits the decoder ignores. An encoder leaves them
	// zero, which would confine that character to sixteen of the sixty-four
	// values on every connection - a bias an observer can count. Fill them
	// with noise instead; the decoder discards them either way.
	var noise [1]byte
	if _, err := rand.Read(noise[:]); err != nil {
		return 0, fmt.Errorf("obfs: failed to draw opening noise: %w", err)
	}
	last := encodedPrologueSize - 1
	dst[last] = prologueAlphabet[prologueIndex[dst[last]]|(noise[0]&0x03)]

	if pad > 0 {
		if err := fillPrintable(dst[encodedPrologueSize : encodedPrologueSize+pad]); err != nil {
			return 0, err
		}
	}
	return encodedPrologueSize + pad, nil
}

// decodeWirePrologue recovers the prologue from its encoded form.
func decodeWirePrologue(dst, wire []byte) error {
	if len(wire) != encodedPrologueSize {
		return fmt.Errorf("obfs: encoded prologue is %d bytes, expected %d", len(wire), encodedPrologueSize)
	}
	n, err := prologueCoding.Decode(dst, wire)
	if err != nil {
		return fmt.Errorf("obfs: encoded prologue did not decode: %w", err)
	}
	if n != saltSize {
		return fmt.Errorf("obfs: encoded prologue decoded to %d bytes, expected %d", n, saltSize)
	}
	return nil
}

// fillPrintable fills b with bytes drawn from the same alphabet as the
// encoded prologue, so the pad continues the opening rather than ending it.
func fillPrintable(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("obfs: failed to draw an opening pad: %w", err)
	}
	for i, v := range b {
		b[i] = prologueAlphabet[v&0x3f]
	}
	return nil
}
