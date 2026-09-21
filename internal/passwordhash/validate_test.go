package passwordhash

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Validate is what the account file is read through, so it has to agree with
// Verify exactly: a string Verify would refuse must not reach the store, and
// a string the store accepts must be checkable.
func TestValidateAnswersTheSameQuestionAsVerify(t *testing.T) {
	good, err := Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	hashes := []string{
		good,
		"",
		"not-a-hash",
		phc("m=65536,t=0,p=1", goodSalt, goodTag),
		phc("m=65536,t=3,p=1,x=9", goodSalt, goodTag),
		phc("m=65536,t=3,p=1", goodSalt, ""),
		phc("m=65536,t=3,p=1", "!!!", goodTag),
	}

	for _, s := range hashes {
		_, panicked, verifyErr := verifyOrPanic("password", s)
		if panicked != nil {
			t.Fatalf("Verify(%q) panicked with %v", s, panicked)
		}
		validateErr := Validate(s)
		if (verifyErr == nil) != (validateErr == nil) {
			t.Fatalf("Validate(%q) = %v but Verify(%q) = %v; they must refuse the same strings", s, validateErr, s, verifyErr)
		}
	}
}

// The bounds exist to keep the process alive, not to make this the only
// Argon2id in the world. A hash written by another tool, with its own cost
// parameters and its own sizes, still has to work - an account file is
// something people import.
func TestAHashFromAnotherToolStillVerifies(t *testing.T) {
	const password = "imported-password"

	cases := []struct {
		name                       string
		memory, iters, parallelism uint32
		saltLen, tagLen            int
	}{
		{"the common web defaults", 19456, 2, 1, 16, 32},
		{"the smallest we accept", minMemory, minIters, minParallelism, minSaltLength, minKeyLength},
		{"the largest we accept", maxMemory, maxIters, maxParallelism, maxSaltLength, maxKeyLength},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			salt := []byte(strings.Repeat("s", c.saltLen))
			tag := argon2.IDKey([]byte(password), salt, c.iters, c.memory, uint8(c.parallelism), uint32(c.tagLen))
			enc := base64.RawStdEncoding
			hash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
				c.memory, c.iters, c.parallelism, enc.EncodeToString(salt), enc.EncodeToString(tag))

			if err := Validate(hash); err != nil {
				t.Fatalf("Validate refused a hash another Argon2id wrote: %v", err)
			}
			ok, err := Verify(password, hash)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("the password that made this hash did not verify")
			}
			ok, err = Verify("wrong", hash)
			if err != nil {
				t.Fatalf("Verify with a wrong password: %v", err)
			}
			if ok {
				t.Fatal("a wrong password verified")
			}
		})
	}
}

// A refusal is only useful if it says which field was wrong: the operator
// reading the log is the person who has to fix the file.
func TestARefusalNamesTheFieldThatIsWrong(t *testing.T) {
	cases := []struct {
		hash string
		want string
	}{
		{phc("m=65536,t=0,p=1", goodSalt, goodTag), "iterations"},
		{phc("m=1,t=3,p=1", goodSalt, goodTag), "memory"},
		{phc("m=65536,t=3,p=0", goodSalt, goodTag), "parallelism"},
		{phc("m=65536,t=3,p=1", "AAAA", goodTag), "salt"},
		{phc("m=65536,t=3,p=1", goodSalt, "AAAA"), "hash"},
		{"$argon2id$v=1$m=65536,t=3,p=1$" + goodSalt + "$" + goodTag, "version"},
		{"$argon2i$v=19$m=65536,t=3,p=1$" + goodSalt + "$" + goodTag, "algorithm"},
	}

	for _, c := range cases {
		err := Validate(c.hash)
		if err == nil {
			t.Fatalf("Validate(%q) accepted it", c.hash)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("Validate(%q) said %q, which does not mention %q", c.hash, err, c.want)
		}
	}
}
