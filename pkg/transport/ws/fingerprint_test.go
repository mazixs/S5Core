package ws

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
	"github.com/mazixs/S5Core/internal/utls"
)

// Level 4 of the checklist, applied to the dialer this transport actually
// uses. internal/stealth/fingerprint_test.go proves the formula is right by
// checking recorded vectors; this file proves the product puts those vectors
// on the wire, which is a different claim and the one TLS_FINGERPRINT makes.
//
// Between the two there is a whole dialer: Dial builds DialOpts, decides
// between uTLS and crypto/tls, derives a server name and hands the result to
// gorilla/websocket. Any of that can stop doing what the setting promises
// without a single test going red - the connection still works, it just stops
// looking like a browser, and looking like a browser is the entire point.
//
// The JA4 values repeat the table in internal/stealth/fingerprint_test.go on
// purpose. If the two lists ever disagree, the dialer is not sending what the
// preset it names contains, and that is worth a failing test rather than a
// shared constant that hides it.
var wireFingerprints = []struct {
	fingerprint string
	ja4         string
}{
	{utls.FPChrome, "t13d1516h2_8daaf6152771_d8a2da3f94cd"},
	{utls.FPFirefox, "t13d1715h2_5b57614c22b0_5c2c66f702b0"},
	{utls.FPSafari, "t13d2014h2_a09f3c656075_14788d8d241b"},
	{utls.FPIOS, "t13d2613h2_2802a3db6c62_845d286b0d67"},
	{utls.FPDefaultGo, "t13d031000_55b375c5d22e_e7c285222651"},
}

func TestTheWSSClientPutsTheNamedFingerprintOnTheWire(t *testing.T) {
	for _, tc := range wireFingerprints {
		t.Run(tc.fingerprint, func(t *testing.T) {
			h := helloOfADial(t, tc.fingerprint, "example.com")
			if got := h.JA4(); got != tc.ja4 {
				t.Errorf("JA4 on the wire\n  want %s\n  got  %s\nuTLS preset moved, or the dialer stopped using it; see docs/field/stealth.md",
					tc.ja4, got)
			}
		})
	}
}

// Without TLS_FINGERPRINT the transport falls back to crypto/tls, and the
// result is not a browser by any measure an observer uses: no GREASE, no ALPN
// offer, a different JA4. This is recorded rather than fixed - the fallback is
// deliberate, and a deployment that does not set the variable should know what
// it is sending.
func TestWithoutAFingerprintTheClientIsRecognisablyNotABrowser(t *testing.T) {
	plain := helloOfADial(t, "", "example.com")
	chrome := helloOfADial(t, utls.FPChrome, "example.com")

	if plain.JA4() == chrome.JA4() {
		t.Fatalf("crypto/tls and the chrome preset produce the same JA4 %s", plain.JA4())
	}
	if plain.HadGREASE {
		t.Error("crypto/tls sent GREASE; the recorded expectation is that it does not")
	}
	if len(plain.ALPN) != 0 {
		t.Errorf("crypto/tls offered ALPN %v; the recorded expectation is none", plain.ALPN)
	}
	if !strings.HasSuffix(strings.Split(plain.JA4(), "_")[0], "00") {
		t.Errorf("JA4_a is %s, want it to end in 00 for an absent ALPN", strings.Split(plain.JA4(), "_")[0])
	}
	t.Logf("crypto/tls: %s, chrome: %s", plain.JA4(), chrome.JA4())
}

// Chrome randomises the order of its extensions on every connection. JA3
// hashes that order, so a JA3 blocklist cannot hold a Chrome entry at all;
// JA4 sorts the list first and identifies the client anyway. Recording this
// is the reason the tests above compare JA4 and not JA3.
func TestChromeShufflesItsJA3ButNotItsJA4(t *testing.T) {
	const runs = 4
	ja3 := make(map[string]bool, runs)
	ja4 := make(map[string]bool, runs)
	for i := 0; i < runs; i++ {
		h := helloOfADial(t, utls.FPChrome, "example.com")
		ja3[h.JA3()] = true
		ja4[h.JA4()] = true
	}
	if len(ja3) == 1 {
		t.Error("JA3 was identical across connections; the chrome preset stopped shuffling its extensions")
	}
	if len(ja4) != 1 {
		t.Errorf("JA4 differed across connections (%d distinct values); it is supposed to be stable", len(ja4))
	}
}

// A deployment dialled by address rather than by name sends no SNI, and the
// fingerprint says so in clear text: JA4_a carries 'i' instead of 'd' and one
// extension fewer. The bytes are still a browser's, but the connection is not
// one a browser would make - nothing loads https://93.184.216.34/ by address.
func TestDialingByAddressIsVisibleInTheFingerprint(t *testing.T) {
	named := helloOfADial(t, utls.FPChrome, "example.com")
	byAddr := helloOfADial(t, utls.FPChrome, "")

	if byAddr.ServerName != "" {
		t.Fatalf("expected no SNI when dialling an address, got %q", byAddr.ServerName)
	}
	a := strings.Split(byAddr.JA4(), "_")[0]
	if a[3] != 'i' {
		t.Errorf("JA4_a is %s, want 'i' in the SNI position", a)
	}
	if named.JA4() == byAddr.JA4() {
		t.Error("the two dials produced the same JA4; the SNI difference is supposed to show")
	}
	t.Logf("with name %s, by address %s", named.JA4(), byAddr.JA4())
}

// helloOfADial captures the ClientHello the transport sends and parses it.
// The listener never replies, so the dial fails - by then the hello is on the
// wire, and it is the only thing under test.
func helloOfADial(t *testing.T, fingerprint, serverName string) *stealth.ClientHello {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	captured := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		// One read: every client here writes its hello in a single write, and
		// a hello split across reads would be a finding of its own.
		buf := make([]byte, 16384)
		n, _ := c.Read(buf)
		captured <- buf[:n]
	}()

	_, _ = Dial(DialOpts{
		URL:            "wss://" + l.Addr().String() + "/ws",
		ServerName:     serverName,
		TLSFingerprint: fingerprint,
		TLSConfig:      &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // соединение до рукопожатия не доходит
	})

	select {
	case raw := <-captured:
		h, err := stealth.ParseClientHello(raw)
		if err != nil {
			t.Fatalf("parse the hello of a %q dial: %v (%d bytes captured)", fingerprint, err, len(raw))
		}
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello captured")
		return nil
	}
}
