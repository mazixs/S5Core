package main

import (
	"strings"

	"golang.org/x/net/idna"
)

// domainMatcher is compiled once per configuration, then shared read-only.
// Each lookup depends on the destination's label count, not the rules count.
type domainMatcher struct{ exact, suffix map[string]struct{} }

func normalizeDomain(s string) string {
	s = strings.ToLower(s)
	if ascii, e := idna.ToASCII(s); e == nil {
		return ascii
	}
	return s
}
func newDomainMatcher(patterns []string) *domainMatcher {
	m := &domainMatcher{exact: make(map[string]struct{}, len(patterns)), suffix: make(map[string]struct{})}
	for _, p := range patterns {
		p = normalizeDomain(strings.TrimSpace(p))
		m.exact[p] = struct{}{}
		if strings.HasPrefix(p, "*.") {
			m.suffix[p[2:]] = struct{}{}
		}
	}
	return m
}
func (m *domainMatcher) Match(fqdn string) bool {
	if m == nil || len(m.exact) == 0 {
		return false
	}
	fqdn = normalizeDomain(fqdn)
	if _, ok := m.exact[fqdn]; ok {
		return true
	}
	for {
		if _, ok := m.suffix[fqdn]; ok {
			return true
		}
		dot := strings.IndexByte(fqdn, '.')
		if dot < 0 {
			return false
		}
		fqdn = fqdn[dot+1:]
	}
}
