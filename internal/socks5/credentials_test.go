package socks5

import (
	"testing"
)

func TestStaticCredentials(t *testing.T) {
	creds := StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	if !creds.Valid("foo", "bar") {
		t.Fatalf("expect valid")
	}

	if !creds.Valid("baz", "") {
		t.Fatalf("expect valid")
	}

	if creds.Valid("foo", "") {
		t.Fatalf("expect invalid")
	}
}

// StaticCredentials enables using a map directly as a credential store.
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
