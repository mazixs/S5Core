package identity

import (
	"errors"
	"testing"
	"time"
)

type unavailableCredentials struct{ available bool }

func (s *unavailableCredentials) Valid(_, password string) bool {
	return s.available && password == "correct"
}
func (s *unavailableCredentials) ValidResult(user, password string) (bool, error) {
	if !s.available {
		return false, errors.New("verification temporarily unavailable")
	}
	return s.Valid(user, password), nil
}

func TestUnavailableCredentialChecksDoNotBanTheSourceOrAccount(t *testing.T) {
	store := &unavailableCredentials{}
	failures := 0
	guard := NewGuard(store, Options{MaxRetries: 2, BanTime: time.Minute, OnAuthFailure: func() { failures++ }})
	for range 20 {
		if guard.ValidFrom("alice", "correct", "192.0.2.1") {
			t.Fatal("unavailable check accepted")
		}
	}
	if failures != 0 {
		t.Fatalf("unavailability counted as %d wrong passwords", failures)
	}
	store.available = true
	if !guard.ValidFrom("alice", "correct", "192.0.2.1") {
		t.Fatal("recovered credentials were banned")
	}
}
