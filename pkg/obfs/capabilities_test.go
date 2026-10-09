package obfs

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCapabilitiesTravelAsTheirOwnField(t *testing.T) {
	wire := encodeAdvice(Advice{Capabilities: CapWSEarlyData})
	if want := []byte{0x08, 2, 0, 1}; !bytes.Equal(wire, want) {
		t.Fatalf("early data encodes to % x, want % x", wire, want)
	}
	// 2.3 and earlier skip a type they do not know: what they read from
	// this advice is "no opinion", the same as before the field existed.
	got, err := decodeAdvice(wire)
	if err != nil || got.Capabilities != CapWSEarlyData {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	got.Capabilities = 0
	if got != (Advice{}) {
		t.Fatalf("capabilities leaked into another field: %+v", got)
	}
	if _, err := decodeAdvice([]byte{0x08, 1, 1}); err == nil {
		t.Fatal("a one-byte capability field was accepted")
	}
}

func TestTheSpecificationListsEveryAdviceField(t *testing.T) {
	spec := readSpec(t)
	start := strings.Index(spec, "### 8.4 ")
	end := strings.Index(spec, "### 8.5 ")
	if start < 0 || end < start {
		t.Fatal("sections 8.4 and 8.5 are missing from the specification")
	}
	section := spec[start:end]
	for _, typ := range []byte{adviceTransport, adviceWSMinFrame, adviceWSMaxFrame, adviceWSMaxJitter,
		adviceMaxPadding, adviceKeepaliveMin, adviceKeepaliveMax, adviceCapabilities} {
		if row := fmt.Sprintf("| `0x%02x` |", typ); !strings.Contains(section, row) {
			t.Errorf("advice type 0x%02x has no row in section 8.4", typ)
		}
	}
	if !strings.Contains(section, fmt.Sprintf("бит %d", 0)) || CapWSEarlyData != 1<<0 {
		t.Error("section 8.4 does not name the bit of early data the code uses")
	}
	if !strings.Contains(spec[end:], "WS_EARLY_DATA") {
		t.Error("section 8.5 does not describe WS_EARLY_DATA")
	}
}
