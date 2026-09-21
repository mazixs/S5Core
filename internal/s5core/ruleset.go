package s5core

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/mazixs/S5Core/internal/socks5"
)

// PermitDestAddrPattern returns a RuleSet which selectively allows addresses.
//
// A pattern with no anchors of its own is anchored to the whole destination.
// Unanchored, the obvious-looking pattern example\.com also allowed
// evil-example.community - the exact failure an allow-list exists to prevent,
// and a silent one, because the rule looks like it works.
//
// A pattern that already anchors itself is left alone: its author is managing
// the anchoring, and wrapping it would break the common idiom
// (^|\.)example\.com$ for "the domain and its subdomains".
//
// Whether it does is decided by parsing the pattern, not by looking for the
// characters ^ and $ in it. A ^ is only an anchor where a regexp reads it as
// one: in [^.] it negates a character class, and \$ is a dollar sign. Both
// used to count as "the author anchored this", so [^.]+\.example\.com was
// left unanchored and allowed ok.example.com.attacker.invalid - the very
// failure the anchoring exists to prevent, in a pattern that looks stricter
// than the plain one (F13 in
// docs/reports/code-quality-audit-2026-09-20.md).
//
// Anchoring wraps the pattern as a whole, so alternatives keep working:
// a|b becomes ^(?:a|b)$ and not ^a|b$.
func PermitDestAddrPattern(pattern string) (socks5.RuleSet, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("destination pattern is empty")
	}
	anchored, err := anchorPattern(pattern)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(anchored)
	if err != nil {
		return nil, err
	}
	return &PermitDestAddrPatternRuleSet{re}, nil
}

// anchorPattern adds the anchors the author did not write. It fails on a
// pattern that does not parse, which regexp.Compile would reject anyway.
func anchorPattern(pattern string) (string, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", err
	}
	if hasAnchor(parsed) {
		return pattern, nil
	}
	return "^(?:" + pattern + ")$", nil
}

// hasAnchor reports whether the pattern contains a position assertion
// anywhere - ^ or $ in either their text or their line form. Anywhere, not
// at the ends: the documented subdomain idiom (^|\.)example\.com$ carries
// its leading anchor inside an alternation, so a test for "starts with an
// anchor" would wrap it and stop it matching subdomains, which is the
// behaviour this pattern is written for.
func hasAnchor(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText:
		return true
	}
	for _, sub := range re.Sub {
		if hasAnchor(sub) {
			return true
		}
	}
	return false
}

// PermitDestAddrPatternRuleSet is an implementation of the RuleSet which
// enables filtering supported destination address
type PermitDestAddrPatternRuleSet struct {
	AllowedFqdnPattern *regexp.Regexp
}

// Allow matches the destination as the client asked for it: the name when the
// client sent a name, the literal address when it sent an address.
//
// The distinction matters because the rule is checked before the name is
// resolved. Matching a resolved address against a name pattern would never
// work, and matching nothing at all - which is what an empty FQDN used to do -
// quietly turned every IP-literal request into a refusal with no way to allow
// one.
func (p *PermitDestAddrPatternRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if isUDPSetup(req) {
		// The address in a UDP ASSOCIATE request is the client's side of the
		// association, not a destination: it is where the client says it will
		// send from, and RFC 1928 lets it be 0.0.0.0:0, which most clients
		// send. Matching it against a destination pattern answered a question
		// nobody asked - it refused every well-behaved client outright, and
		// let one that wrote an allowed address there open an association it
		// could then use to reach anything (F02 in
		// docs/reports/code-quality-audit-2026-09-20.md).
		//
		// The destinations of that association are checked one datagram at a
		// time, which is the only point at which a UDP destination exists.
		return ctx, true
	}
	dest := destinationString(req)
	if dest == "" {
		return ctx, false
	}
	return ctx, p.AllowedFqdnPattern.MatchString(dest)
}

// isUDPSetup reports whether this is the request that opens a UDP
// association, as opposed to one of its datagrams.
func isUDPSetup(req *socks5.Request) bool {
	if req == nil || req.Datagram {
		return false
	}
	return req.Command == socks5.AssociateCommand || req.Command == socks5.UDPTunnelCommand
}

// destinationString is what the client asked for, in the form it asked for it,
// with one normalisation: a name is lower-cased.
//
// DNS names are case-insensitive over ASCII (RFC 4343), so EXAMPLE.COM and
// example.com are one destination and an allow-list that let one through and
// not the other would be answering a question nobody asked. The case is
// folded on the name rather than by compiling the pattern with (?i), because
// (?i) in Go folds Unicode too: an ASCII pattern would then also be satisfied
// by a name built from lookalikes such as U+212A KELVIN SIGN, which is the
// opposite of what an allow-list is for. Patterns are therefore written in
// lower case; an upper-case letter in a literal simply never matches.
func destinationString(req *socks5.Request) string {
	if req == nil || req.DestAddr == nil {
		return ""
	}
	if req.DestAddr.FQDN != "" {
		// A trailing dot is the same name; strip it so that a pattern does not
		// have to know about the root label.
		return asciiLower(strings.TrimSuffix(req.DestAddr.FQDN, "."))
	}
	if len(req.DestAddr.IP) > 0 {
		return req.DestAddr.IP.String()
	}
	return ""
}

// asciiLower folds A-Z and leaves every other byte alone. strings.ToLower
// would fold Unicode as well, which is the case distinction DNS does not
// make and an attacker does.
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'A' || c > 'Z' {
			continue
		}
		if b == nil {
			b = []byte(s)
		}
		b[i] = c + ('a' - 'A')
	}
	if b == nil {
		return s
	}
	return string(b)
}
