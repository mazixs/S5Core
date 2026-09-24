package stealth

import "testing"

// The examples of the JA4 specification (FoxIO, "ALPN Extension Value").
func TestJA4ALPNFollowsTheSpecification(t *testing.T) {
	for _, tc := range []struct {
		alpn []string
		want string
	}{
		{nil, "00"},
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h"}, "hh"},
		{[]string{"\xab"}, "ab"},
		{[]string{"\xab\xcd"}, "ad"},
		{[]string{"0\xab"}, "3b"},
		{[]string{"01\xab\xcd"}, "3d"},
		{[]string{"0\xab1"}, "01"},
		{[]string{"_x"}, "58"},
	} {
		if got := ja4ALPN(tc.alpn); got != tc.want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", tc.alpn, got, tc.want)
		}
	}
}
