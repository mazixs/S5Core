package ws

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
	"github.com/mazixs/S5Core/internal/utls"
)

// Gate G3 of the plan asks whether the level-1 checklist - the
// fully-encrypted-traffic policy that blocks a first packet matching no
// exemption - is passed by the product as it stands.
//
// For the plain obfuscated listener the answer is recorded in
// pkg/obfs/demo_test.go and it is no: 98.9% of first packets match no
// exemption. This test records the other half of the answer. Over WSS the
// first packet of a connection is not an obfuscated frame at all, it is a TLS
// ClientHello, and a ClientHello is exempt - so the level-1 defect belongs to
// one of the two listeners rather than to the product.
func TestTheFirstPacketOfAWSSClientIsExempt(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fingerprint string
	}{
		{"crypto/tls", ""},
		{"uTLS chrome", utls.FPChrome},
		{"uTLS firefox", utls.FPFirefox},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := firstPacketOfADial(t, tc.fingerprint)
			ex := stealth.Exempt(first)
			if ex == stealth.ExNone {
				t.Fatalf("the first packet of a WSS connection matches no exemption: %d bytes, %.3f bits per byte",
					len(first), stealth.BitsPerByte(first))
			}
			t.Logf("%d bytes, %.3f bits per byte, %s", len(first), stealth.BitsPerByte(first), ex)
		})
	}
}

// firstPacketOfADial captures what a client puts on the wire before the
// server has said anything. The listener never answers, so the dial fails -
// the first packet has already been sent by then, and it is the only thing
// this test is about.
func firstPacketOfADial(t *testing.T, fingerprint string) []byte {
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
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		captured <- buf[:n]
	}()

	_, _ = Dial(DialOpts{
		URL:            "wss://" + l.Addr().String() + "/ws",
		TLSFingerprint: fingerprint,
		TLSConfig:      &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // соединение до рукопожатия не доходит
	})

	select {
	case p := <-captured:
		if len(p) == 0 {
			t.Fatal("the client sent nothing")
		}
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no first packet captured")
		return nil
	}
}
