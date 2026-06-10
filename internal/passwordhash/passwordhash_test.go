package passwordhash

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := "super-secret-password"

	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("Unexpected hash format: %s", hash)
	}

	// Correct password
	ok, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !ok {
		t.Fatal("Verify should have succeeded for correct password")
	}

	// Incorrect password
	ok, err = Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if ok {
		t.Fatal("Verify should have failed for wrong password")
	}
}

func TestVerifyEmptyHash(t *testing.T) {
	ok, err := Verify("password", "")
	if err == nil {
		t.Fatal("Expected error for empty hash")
	}
	if ok {
		t.Fatal("Expected false for empty hash")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	cases := []string{
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=1$salt$hash",
		"$argon2id$v=1$m=65536,t=3,p=1$salt$hash",
		"$argon2id$v=19$m=65536,t=3,p=1$!!!$hash",
	}

	for _, c := range cases {
		ok, err := Verify("password", c)
		if err == nil {
			t.Fatalf("Expected error for malformed hash %q", c)
		}
		if ok {
			t.Fatalf("Expected false for malformed hash %q", c)
		}
	}
}

func TestVerifyUnsafeParameters(t *testing.T) {
	// Craft a hash with memory way above the safe limit
	unsafeHash := "$argon2id$v=19$m=999999999,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := Verify("password", unsafeHash)
	if err == nil {
		t.Error("expected error for unsafe argon2 parameters")
	}
	if ok {
		t.Error("expected Verify to return false for unsafe parameters")
	}
}

func TestDifferentPasswordsProduceDifferentHashes(t *testing.T) {
	h1, _ := Hash("password1")
	h2, _ := Hash("password1") // same password, should still differ due to random salt

	if h1 == h2 {
		t.Fatal("Hashes of the same password should differ due to random salt")
	}
}
