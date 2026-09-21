package s5core

import (
	"context"
	"net"
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

// The pattern everybody writes first. Unanchored it allowed
// evil-example.community, which is an allow-list letting through the one kind
// of host it was put there to keep out.
func TestUnanchoredPatternDoesNotMatchASuffixOrPrefix(t *testing.T) {
	rs, err := PermitDestAddrPattern(`example\.com`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		fqdn    string
		allowed bool
	}{
		{"example.com", true},
		{"example.com.", true}, // the same name, written with the root label
		{"evil-example.community", false},
		{"example.community", false},
		{"notexample.com", false},
		{"example.com.evil.net", false},
		{"sub.example.com", false}, // a pattern for the domain is not a pattern for its subdomains
	}

	for _, tt := range tests {
		req := &socks5.Request{DestAddr: &socks5.AddrSpec{FQDN: tt.fqdn}}
		if _, allowed := rs.Allow(context.Background(), req); allowed != tt.allowed {
			t.Errorf("FQDN %q: expected allowed=%v, got %v", tt.fqdn, tt.allowed, allowed)
		}
	}
}

// A client that resolves the name itself and sends an address used to be
// refused whatever the rule said, because the rule was matched against an
// empty string. Now the literal is matched as written, so it can be allowed
// deliberately - and is still refused by a name-only pattern.
func TestIPLiteralIsMatchedAsWritten(t *testing.T) {
	names, err := PermitDestAddrPattern(`example\.com`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := &socks5.Request{DestAddr: &socks5.AddrSpec{IP: net.ParseIP("203.0.113.5")}}
	if _, allowed := names.Allow(context.Background(), req); allowed {
		t.Error("a name-only pattern allowed an IP literal")
	}

	addrs, err := PermitDestAddrPattern(`203\.0\.113\.\d+`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, allowed := addrs.Allow(context.Background(), req); !allowed {
		t.Error("an address pattern did not allow the address it names")
	}
	other := &socks5.Request{DestAddr: &socks5.AddrSpec{IP: net.ParseIP("198.51.100.5")}}
	if _, allowed := addrs.Allow(context.Background(), other); allowed {
		t.Error("an address pattern allowed an address outside it")
	}
}

func TestEmptyPatternIsRejected(t *testing.T) {
	if _, err := PermitDestAddrPattern("   "); err == nil {
		t.Error("an empty pattern was accepted; it would allow nothing and say nothing")
	}
}

// F13. A ^ is an anchor only where a regexp reads it as one. Inside a
// character class it negates the class, and an escaped $ is a dollar sign -
// neither says anything about where the match may start or end. Treating
// them as anchors left the pattern unanchored, so a rule that looks stricter
// than the plain one was the one that let a suffix through.
func TestAnchoringLooksAtTheParseTreeNotTheCharacters(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		dest    string
		allowed bool
	}{
		{
			name:    "negated class is not an anchor",
			pattern: `[^.]+\.example\.com`,
			dest:    "ok.example.com.attacker.invalid",
			allowed: false,
		},
		{
			name:    "and still matches what it is for",
			pattern: `[^.]+\.example\.com`,
			dest:    "ok.example.com",
			allowed: true,
		},
		{
			name:    "a negated class may not match a dot either",
			pattern: `[^.]+\.example\.com`,
			dest:    "deep.sub.example.com",
			allowed: false,
		},
		{
			name:    "an escaped dollar is a dollar",
			pattern: `pay\$day\.example\.com`,
			dest:    "pay$day.example.com.attacker.invalid",
			allowed: false,
		},
		{
			name:    "an escaped caret is a caret",
			pattern: `\^weird\.example\.com`,
			dest:    "^weird.example.com.attacker.invalid",
			allowed: false,
		},
		{
			name:    "alternatives are wrapped as a whole",
			pattern: `a\.example\.com|b\.example\.com`,
			dest:    "b.example.com.attacker.invalid",
			allowed: false,
		},
		{
			name:    "both alternatives still match",
			pattern: `a\.example\.com|b\.example\.com`,
			dest:    "b.example.com",
			allowed: true,
		},
		{
			name:    "a real anchor is still the author's business",
			pattern: `(^|\.)example\.com$`,
			dest:    "deep.sub.example.com",
			allowed: true,
		},
		{
			name:    "a class inside an anchored pattern is left alone",
			pattern: `^[^.]+\.example\.com$`,
			dest:    "ok.example.com",
			allowed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := PermitDestAddrPattern(tc.pattern)
			if err != nil {
				t.Fatalf("PermitDestAddrPattern(%q): %v", tc.pattern, err)
			}
			req := &socks5.Request{DestAddr: &socks5.AddrSpec{FQDN: tc.dest}}
			if _, allowed := rs.Allow(context.Background(), req); allowed != tc.allowed {
				t.Errorf("pattern %q against %q: allowed=%v, want %v",
					tc.pattern, tc.dest, allowed, tc.allowed)
			}
		})
	}
}

// F13, the other half: a DNS name is case-insensitive over ASCII, so the
// allow-list answers the same for either spelling. The folding is ASCII-only
// on purpose - a Unicode fold would let a lookalike satisfy an ASCII pattern,
// which is the opposite of an allow-list.
func TestANameIsMatchedWithoutRegardToItsCase(t *testing.T) {
	rs, err := PermitDestAddrPattern(`(^|\.)example\.com$`)
	if err != nil {
		t.Fatalf("PermitDestAddrPattern: %v", err)
	}
	for _, dest := range []string{"EXAMPLE.COM", "Example.Com", "SUB.example.COM", "example.com."} {
		req := &socks5.Request{DestAddr: &socks5.AddrSpec{FQDN: dest}}
		if _, allowed := rs.Allow(context.Background(), req); !allowed {
			t.Errorf("%q was refused by a rule that allows example.com", dest)
		}
	}
	// The fold is ASCII. U+212A KELVIN SIGN lower-cases to "k" under Unicode
	// rules, and a name carrying it is not the name the rule allows.
	req := &socks5.Request{DestAddr: &socks5.AddrSpec{FQDN: "Keys.example.com"}}
	if _, allowed := rs.Allow(context.Background(), req); !allowed {
		t.Error("a subdomain is a subdomain whatever its first label holds")
	}
	rs2, err := PermitDestAddrPattern(`^keys\.example\.com$`)
	if err != nil {
		t.Fatalf("PermitDestAddrPattern: %v", err)
	}
	if _, allowed := rs2.Allow(context.Background(), req); allowed {
		t.Error("a Unicode lookalike satisfied an ASCII pattern")
	}
}

// A pattern that does not parse is refused where it is written, not where it
// is used.
func TestAPatternThatDoesNotParseIsRefused(t *testing.T) {
	for _, pattern := range []string{`[unclosed`, `(?P<`, `a{2,1}`} {
		if _, err := PermitDestAddrPattern(pattern); err == nil {
			t.Errorf("PermitDestAddrPattern(%q) accepted a pattern that does not parse", pattern)
		}
	}
}

// The address in a UDP ASSOCIATE request is the client's own, and RFC 1928
// lets a client that does not know it in advance send 0.0.0.0:0. Matching that
// against a destination pattern refused every such client, and accepted the
// one that wrote an allowed address there - after which the association could
// be used to reach anything, because nothing checked again (F02).
func TestAUDPSetupIsNotADestination(t *testing.T) {
	rs, err := PermitDestAddrPattern(`^example\.com$`)
	if err != nil {
		t.Fatalf("PermitDestAddrPattern: %v", err)
	}
	for _, command := range []byte{socks5.AssociateCommand, socks5.UDPTunnelCommand} {
		for _, addr := range []*socks5.AddrSpec{
			{IP: net.IPv4zero, Port: 0},
			{IP: net.ParseIP("198.51.100.7"), Port: 5353},
			{FQDN: "blocked.invalid", Port: 0},
		} {
			req := &socks5.Request{Command: command, DestAddr: addr}
			if _, allowed := rs.Allow(context.Background(), req); !allowed {
				t.Errorf("command 0x%02x with client address %q was refused by a destination rule",
					command, addr.Address())
			}
		}
	}

	// And the datagrams of that association are answered on their own merits,
	// which is where the rule actually applies.
	allowed := &socks5.Request{
		Command:  socks5.AssociateCommand,
		DestAddr: &socks5.AddrSpec{FQDN: "example.com", Port: 53},
		Datagram: true,
	}
	if _, ok := rs.Allow(context.Background(), allowed); !ok {
		t.Error("a datagram to the allowed name was refused")
	}
	blocked := &socks5.Request{
		Command:  socks5.AssociateCommand,
		DestAddr: &socks5.AddrSpec{FQDN: "blocked.invalid", Port: 53},
		Datagram: true,
	}
	if _, ok := rs.Allow(context.Background(), blocked); ok {
		t.Error("a datagram to a name outside the rule was allowed")
	}
}

// CONNECT is unaffected: the destination of a CONNECT request is a
// destination, and the exemption above must not reach it.
func TestAConnectRequestIsStillMatched(t *testing.T) {
	rs, err := PermitDestAddrPattern(`^example\.com$`)
	if err != nil {
		t.Fatalf("PermitDestAddrPattern: %v", err)
	}
	req := &socks5.Request{
		Command:  socks5.ConnectCommand,
		DestAddr: &socks5.AddrSpec{FQDN: "blocked.invalid", Port: 443},
	}
	if _, allowed := rs.Allow(context.Background(), req); allowed {
		t.Error("a CONNECT to a name outside the rule was allowed")
	}
}
