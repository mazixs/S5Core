package s5core

import (
	"context"
	"testing"

	"github.com/mazixs/S5Core/internal/socks5"
)

func TestPermitDestAddrPattern_ValidRegex(t *testing.T) {
	rs, err := PermitDestAddrPattern(`^example\.com$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rs == nil {
		t.Fatal("expected non-nil RuleSet")
	}
}

func TestPermitDestAddrPattern_InvalidRegex(t *testing.T) {
	_, err := PermitDestAddrPattern(`[invalid`)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestAllow_MatchingFQDN(t *testing.T) {
	rs, err := PermitDestAddrPattern(`^example\.com$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := &socks5.Request{
		DestAddr: &socks5.AddrSpec{FQDN: "example.com"},
	}

	_, allowed := rs.Allow(context.Background(), req)
	if !allowed {
		t.Error("expected request to example.com to be allowed")
	}
}

func TestAllow_NonMatchingFQDN(t *testing.T) {
	rs, err := PermitDestAddrPattern(`^example\.com$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := &socks5.Request{
		DestAddr: &socks5.AddrSpec{FQDN: "evil.com"},
	}

	_, allowed := rs.Allow(context.Background(), req)
	if allowed {
		t.Error("expected request to evil.com to be denied")
	}
}

func TestAllow_SubdomainPattern(t *testing.T) {
	rs, err := PermitDestAddrPattern(`(^|\.)example\.com$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		fqdn    string
		allowed bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		req := &socks5.Request{
			DestAddr: &socks5.AddrSpec{FQDN: tt.fqdn},
		}
		_, allowed := rs.Allow(context.Background(), req)
		if allowed != tt.allowed {
			t.Errorf("FQDN %q: expected allowed=%v, got %v", tt.fqdn, tt.allowed, allowed)
		}
	}
}
