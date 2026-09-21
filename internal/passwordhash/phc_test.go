package passwordhash

import (
	"strings"
	"testing"
)

// A PHC string is read out of the account file, which an operator edits by
// hand and a migration from another tool writes. It is therefore input, and
// the only acceptable answer to bad input is an error: Argon2id answers some
// of it with a panic instead, and a panic on the authentication path stops
// the process for every other account too.
//
// The three strings the audit found (F15) are named in the table below, so
// that the cases that were actually observed to crash stay visible next to
// the ones reasoning added.

const (
	// What Hash writes: 16 bytes of salt, a 32 byte tag.
	goodSalt = "AAAAAAAAAAAAAAAAAAAAAA"
	goodTag  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func phc(params, salt, tag string) string {
	return "$argon2id$v=19$" + params + "$" + salt + "$" + tag
}

// verifyOrPanic reports what Verify did, turning a panic into a description
// rather than a dead test binary.
func verifyOrPanic(password, hash string) (ok bool, panicked any, err error) {
	defer func() { panicked = recover() }()
	ok, err = Verify(password, hash)
	return ok, nil, err
}

func TestNoHashStringMakesTheVerifierPanic(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		// The three from the audit.
		{"empty tag (nil dereference)", phc("m=8,t=1,p=1", "c2FsdA", "")},
		{"no rounds (number of rounds too small)", phc("m=65536,t=0,p=1", goodSalt, goodTag)},
		{"no parallelism (parallelism degree too low)", phc("m=65536,t=3,p=0", goodSalt, goodTag)},

		// Signed numbers became enormous unsigned ones.
		{"negative memory", phc("m=-1,t=3,p=1", goodSalt, goodTag)},
		{"negative rounds", phc("m=65536,t=-1,p=1", goodSalt, goodTag)},
		{"negative parallelism", phc("m=65536,t=3,p=-1", goodSalt, goodTag)},

		// Numbers that do not fit, or are not numbers.
		{"memory past uint32", phc("m=99999999999999999999,t=3,p=1", goodSalt, goodTag)},
		{"memory is a word", phc("m=lots,t=3,p=1", goodSalt, goodTag)},
		{"memory is missing", phc("m=,t=3,p=1", goodSalt, goodTag)},
		{"memory is a float", phc("m=65536.0,t=3,p=1", goodSalt, goodTag)},
		{"memory has an underscore", phc("m=65_536,t=3,p=1", goodSalt, goodTag)},
		{"memory is hexadecimal", phc("m=0x10000,t=3,p=1", goodSalt, goodTag)},

		// Fields that are not what they claim.
		{"a tail after the parameters", phc("m=65536,t=3,p=1,x=9", goodSalt, goodTag)},
		{"parameters out of order", phc("t=3,m=65536,p=1", goodSalt, goodTag)},
		{"one parameter missing", phc("m=65536,t=3", goodSalt, goodTag)},
		{"a tail after the version", "$argon2id$v=190$m=65536,t=3,p=1$" + goodSalt + "$" + goodTag},
		{"a word after the version", "$argon2id$v=19x$m=65536,t=3,p=1$" + goodSalt + "$" + goodTag},
		{"no leading dollar", "argon2id$v=19$m=65536,t=3,p=1$" + goodSalt + "$" + goodTag + "$"},

		// Sizes nobody writes.
		{"salt too short", phc("m=65536,t=3,p=1", "AAAA", goodTag)},
		{"salt too long", phc("m=65536,t=3,p=1", strings.Repeat("A", 128), goodTag)},
		{"tag too short", phc("m=65536,t=3,p=1", goodSalt, "AAAA")},
		{"tag too long", phc("m=65536,t=3,p=1", goodSalt, strings.Repeat("A", 128))},

		// Costs outside the range this server will pay.
		{"memory above the cap", phc("m=999999,t=3,p=1", goodSalt, goodTag)},
		{"rounds above the cap", phc("m=65536,t=11,p=1", goodSalt, goodTag)},
		{"parallelism above the cap", phc("m=65536,t=3,p=5", goodSalt, goodTag)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, panicked, err := verifyOrPanic("password", c.hash)
			if panicked != nil {
				t.Fatalf("Verify(%q) panicked with %v; a hash string is input, and input has to come back as an error", c.hash, panicked)
			}
			if err == nil {
				t.Fatalf("Verify(%q) returned no error; this string is not a hash a password can be checked against", c.hash)
			}
			if ok {
				t.Fatalf("Verify(%q) accepted the password", c.hash)
			}
		})
	}
}
