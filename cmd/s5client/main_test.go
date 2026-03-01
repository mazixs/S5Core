package main

import "testing"

func TestMatchDomain(t *testing.T) {
	patterns := []string{"example.com", "*.google.com"}

	tests := []struct {
		fqdn    string
		matched bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true}, // case insensitive
		{"other.com", false},
		{"sub.example.com", false},    // not wildcard for example.com
		{"google.com", true},          // *.google.com also matches google.com
		{"www.google.com", true},      // wildcard match
		{"deep.sub.google.com", true}, // deep wildcard
		{"notgoogle.com", false},
	}

	for _, tt := range tests {
		result := matchDomain(tt.fqdn, patterns)
		if result != tt.matched {
			t.Errorf("matchDomain(%q, %v) = %v, want %v", tt.fqdn, patterns, result, tt.matched)
		}
	}
}

func TestMatchDomain_EmptyPatterns(t *testing.T) {
	if matchDomain("example.com", nil) {
		t.Error("expected no match with empty patterns")
	}
	if matchDomain("example.com", []string{}) {
		t.Error("expected no match with empty patterns")
	}
}
