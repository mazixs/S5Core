package passwordhash

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func phcString(p params, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.memory, p.iterations, p.parallelism, phcEncoding.EncodeToString(salt), phcEncoding.EncodeToString(hash))
}

// cheapParams are parameters small enough to run Argon2id on every
// iteration. Everything above is parsed and checked, never computed.
func cheapParams(p params) bool { return p.memory <= 64 && p.iterations <= 2 }

// FuzzParsePHC reads arbitrary strings as stored password hashes - one line
// of the users file an operator edits by hand (audit finding F15):
//   - parsing never panics, and Validate agrees with it;
//   - whatever is accepted is within the documented bounds - memory 8 KiB to
//     512 MiB, 1 to 10 passes, 1 to 4 lanes, a salt of 8 to 64 bytes and a tag
//     of 16 to 64 - so no string makes Verify ask for more;
//   - the canonical spelling of what was parsed parses to the same values;
//   - Standardise keeps the values, only ever changes an accepted string into
//     one it leaves alone, and never touches the standard spelling;
//   - with parameters cheap enough to compute, Verify is the Argon2id tag
//     comparison: true for the password a tag was made from and false for
//     another.
func FuzzParsePHC(f *testing.F) {
	salt := []byte("0123456789abcdef")
	tag := bytes.Repeat([]byte{0x11}, 32)
	f.Add(phcString(params{memory, iterations, parallelism}, salt, tag), "password")
	f.Add(phcString(params{8, 1, 1}, salt[:8], tag[:16]), "")
	f.Add(phcString(params{64, 2, 4}, bytes.Repeat([]byte{0xfb}, 64), bytes.Repeat([]byte{0xff}, 64)), "x")
	f.Add(fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=1$%s$%s", legacyEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6}), legacyEncoding.EncodeToString(bytes.Repeat([]byte{0xfe}, 16))), "legacy")
	f.Add("$argon2id$v=19$m=-1,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "")
	f.Add("$argon2id$v=19$m=65536,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "")
	f.Add("$argon2id$v=19$m=65536,t=3,p=1,x=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "")
	f.Add("$argon2id$v=19$m=64,t=1,p=1$c2Fs\ndHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "")
	f.Add("$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, s, password string) {
		p, salt, hash, err := parse(s)
		if (Validate(s) == nil) != (err == nil) {
			t.Fatalf("Validate and parse disagree on %q", s)
		}
		std, changed := Standardise(s)
		if !changed && std != s {
			t.Fatalf("Standardise changed %q to %q and said it did not", s, std)
		}
		if err != nil {
			return
		}

		if p.memory < minMemory || p.memory > maxMemory || p.iterations < minIters || p.iterations > maxIters ||
			p.parallelism < minParallelism || p.parallelism > maxParallelism {
			t.Fatalf("accepted parameters %+v outside the bounds", p)
		}
		if len(salt) < minSaltLength || len(salt) > maxSaltLength || len(hash) < minKeyLength || len(hash) > maxKeyLength {
			t.Fatalf("accepted a salt of %d and a tag of %d bytes", len(salt), len(hash))
		}

		canon := phcString(p, salt, hash)
		p2, salt2, hash2, err := parse(canon)
		if err != nil || p2 != p || !bytes.Equal(salt2, salt) || !bytes.Equal(hash2, hash) {
			t.Fatalf("the canonical spelling %q of %q parsed differently: %v", canon, s, err)
		}
		if again, changed := Standardise(canon); changed || again != canon {
			t.Fatalf("Standardise rewrote the standard spelling %q", canon)
		}

		p3, salt3, hash3, err := parse(std)
		if err != nil || p3 != p || !bytes.Equal(salt3, salt) || !bytes.Equal(hash3, hash) {
			t.Fatalf("Standardise turned %q into %q, which parses differently: %v", s, std, err)
		}
		if again, changed := Standardise(std); changed || again != std {
			t.Fatalf("Standardise is not idempotent on %q", std)
		}

		if !cheapParams(p) {
			return
		}
		want := bytes.Equal(argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, uint32(len(hash))), hash)
		if ok, err := Verify(password, s); err != nil || ok != want {
			t.Fatalf("Verify = %v, %v, the tag comparison says %v", ok, err, want)
		}
		made := phcString(p, salt, argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, uint32(len(hash))))
		if ok, err := Verify(password, made); err != nil || !ok {
			t.Fatalf("the right password was refused by %q: %v", made, err)
		}
		if ok, _ := Verify(password+"\x00", made); ok {
			t.Fatalf("a different password was accepted by %q", made)
		}
	})
}
