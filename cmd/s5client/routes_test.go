package main

import "testing"

func TestCompiledRoutesBoundaries(t *testing.T) {
	m := newDomainMatcher([]string{"  *.EXAMPLE.com  ", "*.münchen.de", "exact.test", "trailing.test."})
	for _, name := range []string{"example.com", "sub.example.com", "deep.sub.example.com", "MÜNCHEN.DE", "www.xn--mnchen-3ya.de", "exact.test", "trailing.test."} {
		if !m.Match(name) {
			t.Errorf("rejected %q", name)
		}
	}
	for _, name := range []string{"notexample.com", "example.com.evil", "sub.exact.test", "trailing.test", "example.com.", " example.com", "other.test"} {
		if m.Match(name) {
			t.Errorf("accepted %q", name)
		}
	}
}
