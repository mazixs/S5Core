package passwordhash

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Audit finding P3-1: the PHC string has to be spelled in the standard base64
// alphabet, so that a hash written here can be verified by any other Argon2id
// implementation - and a hash written by an earlier build, in the URL-safe
// alphabet, has to keep working until it is rewritten.

// legacyHash spells a hash the way builds before this change did.
func legacyHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	parts := strings.Split(hash, "$")
	for _, i := range [...]int{4, 5} {
		raw, err := base64.RawStdEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatalf("decode field %d: %v", i, err)
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return strings.Join(parts, "$")
}

func TestAHashIsWrittenInTheStandardAlphabet(t *testing.T) {
	// One hash can miss "+" and "/" by chance, so this asks a few and checks
	// that none of them carries a character the standard alphabet lacks.
	for i := 0; i < 32; i++ {
		hash, err := Hash("the password of the day")
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		parts := strings.Split(hash, "$")
		for _, f := range parts[4:] {
			if strings.ContainsAny(f, "-_") {
				t.Fatalf("hash %q carries a URL-alphabet character", hash)
			}
			if _, err := base64.RawStdEncoding.DecodeString(f); err != nil {
				t.Fatalf("field %q does not decode in the standard alphabet: %v", f, err)
			}
		}
	}
}

func TestAHashFromAnEarlierBuildStillVerifies(t *testing.T) {
	const password = "carried over from the old spelling"
	old := legacyHash(t, password)

	ok, err := Verify(password, old)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("a hash in the URL alphabet no longer verifies")
	}

	ok, err = Verify("not the password", old)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("the wrong password verified against a legacy hash")
	}
}

func TestStandardiseKeepsThePassword(t *testing.T) {
	const password = "respelled, not rehashed"

	// A given hash carries no "-" or "_" about one time in eight, which would
	// make the conversion a no-op and the test vacuous. Draw until one does.
	var old string
	for i := 0; i < 64 && old == ""; i++ {
		if h := legacyHash(t, password); strings.ContainsAny(h, "-_") {
			old = h
		}
	}
	if old == "" {
		t.Fatal("64 draws produced no hash with a URL-only character")
	}

	std, changed := Standardise(old)
	if !changed {
		t.Fatalf("Standardise left a URL-alphabet hash alone: %s", old)
	}
	if strings.ContainsAny(std, "-_") {
		t.Fatalf("standardised hash still carries a URL-alphabet character: %s", std)
	}

	ok, err := Verify(password, std)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("the password stopped verifying after standardising")
	}

	// Standardising is idempotent: a hash already in the standard alphabet is
	// returned untouched and reported as unchanged, so a store that calls this
	// on every load does not rewrite its file forever.
	again, changed := Standardise(std)
	if changed || again != std {
		t.Fatalf("standardising twice changed the hash: %q -> %q", std, again)
	}
}

func TestStandardiseLeavesWhatItCannotParse(t *testing.T) {
	for _, s := range []string{
		"",
		"not a hash",
		"$argon2i$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=1$!!!!$aGFzaA",
	} {
		out, changed := Standardise(s)
		if changed || out != s {
			t.Fatalf("Standardise(%q) = (%q, %v), want it untouched", s, out, changed)
		}
	}
}
