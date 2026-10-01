package veil

import (
	"bytes"
	"testing"
)

// The log id depends on the PSK, the session and the context, as the keys do.
func TestTheLogIDIsNotAKey(t *testing.T) {
	psk := bytes.Repeat([]byte{3}, 32)
	secret := []byte("a shared salt, thirty-two bytes!")
	id, err := LogID(psk, secret, Context{})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := LogID(psk, secret, Context{})
	if id != again {
		t.Fatal("the log id is not deterministic")
	}
	if other, _ := LogID(psk, secret, Context{NodeID: "ams-1"}); other == id {
		t.Error("the context does not reach the log id")
	}
	if other, _ := LogID(bytes.Repeat([]byte{4}, 32), secret, Context{}); other == id {
		t.Error("the PSK does not reach the log id: a recorded prologue would name the connection")
	}
	if _, err := LogID(psk[:31], secret, Context{}); err == nil {
		t.Error("a short PSK gave a log id")
	}
	if _, err := LogID(psk, nil, Context{}); err == nil {
		t.Error("no secret gave a log id")
	}
}
