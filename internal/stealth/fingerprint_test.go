package stealth_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/stealth"
)

// The fingerprints below were taken from the uTLS presets this repository
// ships (v1.8.2) and then checked against an independent implementation on
// 20.09.2026: the same ClientHello was relayed to a third-party service that
// computes JA3 and JA4 itself, and all five profiles matched character for
// character, GREASE handling included. That is what makes these numbers a
// test rather than a restatement of our own code.
//
// A failure here means one of three things, in decreasing order of
// likelihood: uTLS was upgraded and its presets moved (expected - re-record
// with the dump helper described in docs/field/stealth.md), the parser
// changed, or the fingerprint formula changed. Only the first is routine.
var recorded = []struct {
	profile string
	ja3     string
	ja4     string
	grease  bool
	alpn    []string
	// shuffles records whether this preset randomises its extension order.
	// Chrome does, which is exactly why JA4 exists: its JA3 differs on every
	// connection while its JA4 does not move.
	shuffles bool
}{
	{"chrome", "6c1e3961c85d6e126cc8ec7032102b88", "t13d1516h2_8daaf6152771_d8a2da3f94cd", true, []string{"h2", "http/1.1"}, true},
	{"firefox", "b5001237acdf006056b409cc433726b0", "t13d1715h2_5b57614c22b0_5c2c66f702b0", false, []string{"h2", "http/1.1"}, false},
	{"safari", "773906b0efdefa24a7f2b8eb6985bf37", "t13d2014h2_a09f3c656075_14788d8d241b", true, []string{"h2", "http/1.1"}, false},
	{"ios", "656b9a2f4de6ed4909e157482860ab3d", "t13d2613h2_2802a3db6c62_845d286b0d67", true, []string{"h2", "http/1.1"}, false},
	{"go", "f3d2a49b79882b036e6c2fa15716a652", "t13d031000_55b375c5d22e_e7c285222651", false, nil, false},
}

func loadHello(t *testing.T, profile string) *stealth.ClientHello {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "hello-utls-"+profile+".bin"))
	if err != nil {
		t.Fatalf("recorded hello for %s: %v", profile, err)
	}
	h, err := stealth.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", profile, err)
	}
	return h
}

func TestTheRecordedFingerprintsAreReproduced(t *testing.T) {
	for _, tc := range recorded {
		t.Run(tc.profile, func(t *testing.T) {
			h := loadHello(t, tc.profile)
			if got := h.JA3(); got != tc.ja3 {
				t.Errorf("JA3\n  want %s\n  got  %s\n  string %s", tc.ja3, got, h.JA3String())
			}
			if got := h.JA4(); got != tc.ja4 {
				t.Errorf("JA4\n  want %s\n  got  %s", tc.ja4, got)
			}
			if h.HadGREASE != tc.grease {
				t.Errorf("GREASE: want %v, got %v", tc.grease, h.HadGREASE)
			}
			if strings.Join(h.ALPN, ",") != strings.Join(tc.alpn, ",") {
				t.Errorf("ALPN: want %v, got %v", tc.alpn, h.ALPN)
			}
		})
	}
}

// A browser preset has to differ from the standard library, otherwise
// TLS_FINGERPRINT costs a dependency and buys nothing. This is the weakest
// possible statement of that - the hashes simply must not be equal - and it
// survives a uTLS upgrade, which the recorded values above do not.
func TestTheBrowserPresetsDoNotLookLikeGo(t *testing.T) {
	plain := loadHello(t, "go")
	for _, tc := range recorded {
		if tc.profile == "go" {
			continue
		}
		h := loadHello(t, tc.profile)
		if h.JA4() == plain.JA4() {
			t.Errorf("%s has the same JA4 as plain Go: %s", tc.profile, h.JA4())
		}
		if len(h.ALPN) == 0 {
			t.Errorf("%s offers no ALPN; a browser always does, and its absence is a signature on its own", tc.profile)
		}
	}
	if len(plain.ALPN) != 0 {
		t.Errorf("the Go preset now offers ALPN %v; the recorded expectation is that it offers none", plain.ALPN)
	}
}

// GREASE values are random per connection by design. If they reached the
// hashed lists, every connection from the same client would fingerprint
// differently and the whole check would silently pass forever.
func TestGREASEIsKeptOutOfTheHashedLists(t *testing.T) {
	h := loadHello(t, "chrome")
	if !h.HadGREASE {
		t.Fatal("the chrome vector is supposed to contain GREASE; without it this test proves nothing")
	}
	for _, field := range strings.Split(h.JA3String(), ",") {
		for _, v := range strings.Split(field, "-") {
			if v == "" {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("JA3 string contains %q, which is not a number", v)
			}
			if isGREASEValue(uint16(n)) { //nolint:gosec // values come from a parsed 16-bit field
				t.Errorf("JA3 string contains GREASE value %d (0x%04x)", n, n)
			}
		}
	}
}

// isGREASEValue repeats the rule the parser applies, on purpose: a test that
// imported the production predicate would agree with it even when both are
// wrong.
func isGREASEValue(v uint16) bool {
	switch v {
	case 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa:
		return true
	}
	return false
}

// The parser reads bytes that arrive from the network, so every truncation
// has to come back as an error rather than as a panic or as a fingerprint
// computed from half a message.
func TestAMalformedHelloIsRejected(t *testing.T) {
	full, err := os.ReadFile(filepath.Join("testdata", "hello-utls-chrome.bin"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"record header only", full[:5]},
		{"half a hello", full[:len(full)/2]},
		{"not a handshake record", append([]byte{0x17}, full[1:]...)},
		{"server hello", append([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02}, 0x00, 0x00, 0x00)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := stealth.ParseClientHello(tc.in); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}

	// Every prefix must be either parsed or refused, never a panic.
	for i := range full {
		_, _ = stealth.ParseClientHello(full[:i])
	}
}

// The JA4_a block is readable on purpose, and each field of it is a claim
// about the client that an observer can check without any hash at all.
func TestTheReadablePartOfJA4DescribesTheHello(t *testing.T) {
	for _, tc := range recorded {
		t.Run(tc.profile, func(t *testing.T) {
			h := loadHello(t, tc.profile)
			a := strings.Split(h.JA4(), "_")[0]
			if len(a) != 10 {
				t.Fatalf("JA4_a is %q, want 10 characters", a)
			}
			if a[0] != 't' {
				t.Errorf("JA4_a starts with %q, want 't' for TCP", a[0])
			}
			if a[1:3] != "13" {
				t.Errorf("version field is %q, want 13: every preset here offers TLS 1.3", a[1:3])
			}
			if a[3] != 'd' {
				t.Errorf("SNI field is %q, want 'd': the vectors were recorded with a server name", a[3])
			}
			if got, want := a[4:6], twoDigitCount(len(h.CipherSuites)); got != want {
				t.Errorf("cipher count field is %q, want %q", got, want)
			}
			if got, want := a[6:8], twoDigitCount(len(h.Extensions)); got != want {
				t.Errorf("extension count field is %q, want %q", got, want)
			}
			wantALPN := "00"
			if len(h.ALPN) > 0 {
				first := h.ALPN[0]
				wantALPN = string([]byte{first[0], first[len(first)-1]})
			}
			if a[8:10] != wantALPN {
				t.Errorf("ALPN field is %q, want %q", a[8:10], wantALPN)
			}
		})
	}
}

func twoDigitCount(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
