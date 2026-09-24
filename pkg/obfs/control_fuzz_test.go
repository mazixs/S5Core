package obfs

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func cutControlString(s string) string {
	if len(s) > maxControlString {
		return s[:maxControlString]
	}
	return s
}

// clampControlInt is what appendUint16TLV sends for n: nothing for zero or
// less, 65535 for anything larger.
func clampControlInt(n int) int {
	return min(max(n, 0), 0xFFFF)
}

func clampControlSeconds(d time.Duration) time.Duration {
	return time.Duration(clampControlInt(int(d/time.Second))) * time.Second
}

// tlvBoundaries lists the offsets at which a new TLV may start in a payload
// the encoder wrote.
func tlvBoundaries(p []byte) []int {
	at := []int{0}
	for i := 0; i+2 <= len(p); {
		i += 2 + int(p[i+1])
		at = append(at, i)
	}
	return at
}

// withUnknownTLV inserts one field of a type this build does not know at the
// boundary pick selects.
func withUnknownTLV(p []byte, typ byte, value []byte, pick uint8) []byte {
	if len(value) > 255 {
		value = value[:255]
	}
	at := tlvBoundaries(p)
	i := at[int(pick)%len(at)]
	out := append([]byte(nil), p[:i]...)
	out = append(out, typ, byte(len(value)))
	out = append(out, value...)
	return append(out, p[i:]...)
}

// FuzzControlRoundTrip holds hello and advice to their encoders:
//   - decode(encode(x)) is x with strings cut to 32 bytes, numbers clamped to
//     0..65535 and durations to whole seconds in that range;
//   - a field of an unknown type anywhere between the known ones changes
//     nothing, as long as the payload stays within the format's 255 bytes.
func FuzzControlRoundTrip(f *testing.F) {
	f.Add("v2.2.0", "obfs", "ws", 256, 4096, 25, 256, int64(10), int64(25), byte(0x7f), []byte("future"), uint8(1))
	f.Add("", "", "", 0, 0, 0, 0, int64(0), int64(0), byte(0), []byte{}, uint8(0))
	f.Add(strings.Repeat("v", 40), strings.Repeat("t", 33), strings.Repeat("w", 32), -1, 1<<20, 65535, 65536, int64(-5), int64(1<<40), byte(0xff), bytes.Repeat([]byte{1}, 255), uint8(200))

	f.Fuzz(func(t *testing.T, version, transport, advised string, minFrame, maxFrame, jitter, padding int, kaMin, kaMax int64, unknown byte, value []byte, pick uint8) {
		h := Hello{Version: version, Transport: transport}
		wantHello := Hello{Version: cutControlString(version), Transport: cutControlString(transport)}
		encH := encodeHello(h)
		gotH, err := decodeHello(encH)
		if err != nil || gotH != wantHello {
			t.Fatalf("hello %+v came back as %+v, err=%v", wantHello, gotH, err)
		}

		a := Advice{
			Transport: advised, WSMinFrame: minFrame, WSMaxFrame: maxFrame, WSMaxJitterMs: jitter,
			MaxPadding: padding, KeepaliveMin: time.Duration(kaMin), KeepaliveMax: time.Duration(kaMax),
		}
		wantAdvice := Advice{
			Transport:  cutControlString(advised),
			WSMinFrame: clampControlInt(minFrame), WSMaxFrame: clampControlInt(maxFrame),
			WSMaxJitterMs: clampControlInt(jitter), MaxPadding: clampControlInt(padding),
			KeepaliveMin: clampControlSeconds(a.KeepaliveMin), KeepaliveMax: clampControlSeconds(a.KeepaliveMax),
		}
		encA := encodeAdvice(a)
		gotA, err := decodeAdvice(encA)
		if err != nil || gotA != wantAdvice {
			t.Fatalf("advice %+v came back as %+v, err=%v", wantAdvice, gotA, err)
		}
		if len(encH) > maxControlPayload || len(encA) > maxControlPayload {
			t.Fatalf("an encoder wrote %d and %d bytes, the format allows %d", len(encH), len(encA), maxControlPayload)
		}

		if unknown != helloVersion && unknown != helloTransport {
			p := withUnknownTLV(encH, unknown, value, pick)
			got, err := decodeHello(p)
			if len(p) <= maxControlPayload && (err != nil || got != wantHello) {
				t.Fatalf("an unknown field %#x changed the hello: %+v, err=%v", unknown, got, err)
			}
		}
		if unknown == 0 || unknown > adviceKeepaliveMax {
			p := withUnknownTLV(encA, unknown, value, pick)
			got, err := decodeAdvice(p)
			if len(p) <= maxControlPayload && (err != nil || got != wantAdvice) {
				t.Fatalf("an unknown field %#x changed the advice: %+v, err=%v", unknown, got, err)
			}
		}
	})
}

// FuzzDecodeControl reads arbitrary payloads as a hello and as an advice:
//   - a payload over 255 bytes is refused by both, and one whose TLV layout is
//     broken is refused by both (advice refuses more: a known number of the
//     wrong width);
//   - an accepted advice holds numbers inside the 16-bit field and durations
//     in whole seconds;
//   - decoding is a fixed point: encoding what was decoded and decoding it
//     again gives the same value, up to the sender's 32-byte cut.
func FuzzDecodeControl(f *testing.F) {
	f.Add(encodeHello(Hello{Version: "v2.2.0", Transport: "ws"}))
	f.Add(encodeAdvice(Advice{Transport: "ws", WSMinFrame: 256, WSMaxFrame: 4096, KeepaliveMin: 10 * time.Second}))
	f.Add([]byte{adviceWSMinFrame, 1, 0})
	f.Add([]byte{0x7f, 3, 'a', 'b'})
	f.Add([]byte{helloVersion})
	f.Add(bytes.Repeat([]byte{0}, 256))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, p []byte) {
		h, herr := decodeHello(p)
		a, aerr := decodeAdvice(p)
		if len(p) > maxControlPayload && (herr == nil || aerr == nil) {
			t.Fatalf("a %d-byte payload was accepted", len(p))
		}
		if herr != nil && aerr == nil {
			t.Fatalf("the TLV layout was refused as a hello (%v) and accepted as an advice", herr)
		}

		if herr == nil {
			want := Hello{Version: cutControlString(h.Version), Transport: cutControlString(h.Transport)}
			if again, err := decodeHello(encodeHello(h)); err != nil || again != want {
				t.Fatalf("hello %+v re-decoded as %+v, err=%v", want, again, err)
			}
		}
		if aerr != nil {
			return
		}
		for _, n := range []int{a.WSMinFrame, a.WSMaxFrame, a.WSMaxJitterMs, a.MaxPadding} {
			if n < 0 || n > 0xFFFF {
				t.Fatalf("an advice number %d is outside its 16-bit field", n)
			}
		}
		for _, d := range []time.Duration{a.KeepaliveMin, a.KeepaliveMax} {
			if d < 0 || d%time.Second != 0 || d > 0xFFFF*time.Second {
				t.Fatalf("an advice duration %v is not whole seconds within the field", d)
			}
		}
		want := a
		want.Transport = cutControlString(a.Transport)
		if again, err := decodeAdvice(encodeAdvice(a)); err != nil || again != want {
			t.Fatalf("advice %+v re-decoded as %+v, err=%v", want, again, err)
		}
	})
}

// FuzzDecodeWirePrologue holds the server's decoder of a printable opening to
// the encoding:
//   - only 43 bytes are ever decoded, and they decode exactly when every one
//     of them is in the alphabet looksEncoded checks - the test the server
//     uses to tell the encodings apart;
//   - what decodes re-encodes to the same characters, except the two noise
//     bits of the last one, which the decoder discards.
func FuzzDecodeWirePrologue(f *testing.F) {
	var p [saltSize]byte
	_, _ = rand.Read(p[:])
	wire := make([]byte, maxWirePrologue)
	n, err := encodeWirePrologue(wire, p[:], openingPadMax)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire[:encodedPrologueSize])
	f.Add(wire[:n])
	f.Add(bytes.Repeat([]byte("A"), encodedPrologueSize))
	f.Add(bytes.Repeat([]byte("/"), encodedPrologueSize))
	f.Add(append(bytes.Repeat([]byte("A"), encodedPrologueSize-1), '\n'))
	f.Add(append(bytes.Repeat([]byte("A"), encodedPrologueSize-1), '='))
	f.Add(p[:])
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, wire []byte) {
		var dst [saltSize]byte
		err := decodeWirePrologue(dst[:], wire)
		if len(wire) != encodedPrologueSize {
			if err == nil {
				t.Fatalf("decoded an opening of %d bytes", len(wire))
			}
			return
		}
		if (err == nil) != looksEncoded(wire) {
			t.Fatalf("decode err=%v but looksEncoded=%v on %q", err, looksEncoded(wire), wire)
		}
		if err != nil {
			return
		}
		again := make([]byte, encodedPrologueSize)
		prologueCoding.Encode(again, dst[:])
		last := encodedPrologueSize - 1
		if !bytes.Equal(again[:last], wire[:last]) || prologueIndex[again[last]] != prologueIndex[wire[last]]&^0x03 {
			t.Fatalf("%q decoded to %x, which encodes as %q", wire, dst, again)
		}
	})
}

// FuzzEncodeWirePrologue: any 32-byte prologue and any pad in 0..20 produce an
// opening of 43+pad printable characters, which the server's own test takes
// for an encoded one and which decodes back to the prologue; the encoder
// writes nothing past it, and refuses a prologue or a pad the format has no
// room for.
func FuzzEncodeWirePrologue(f *testing.F) {
	f.Add(make([]byte, saltSize), 0)
	f.Add(bytes.Repeat([]byte{0xff}, saltSize), openingPadMax)
	f.Add(make([]byte, saltSize-1), 5)
	f.Add(make([]byte, saltSize), openingPadMax+1)
	f.Add(make([]byte, saltSize), -1)
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, prologue []byte, pad int) {
		dst := bytes.Repeat([]byte{0xAA}, maxWirePrologue+4)
		n, err := encodeWirePrologue(dst, prologue, pad)
		if len(prologue) != saltSize || pad < 0 || pad > openingPadMax {
			if err == nil {
				t.Fatalf("encoded a %d-byte prologue with a pad of %d", len(prologue), pad)
			}
			return
		}
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if n != encodedPrologueSize+pad {
			t.Fatalf("an opening of %d bytes for a pad of %d", n, pad)
		}
		if !looksEncoded(dst[:n]) {
			t.Fatalf("the opening %q is not all printable", dst[:n])
		}
		if !bytes.Equal(dst[n:], bytes.Repeat([]byte{0xAA}, len(dst)-n)) {
			t.Fatalf("the encoder wrote past the opening")
		}
		var back [saltSize]byte
		if err := decodeWirePrologue(back[:], dst[:encodedPrologueSize]); err != nil || !bytes.Equal(back[:], prologue) {
			t.Fatalf("the opening decoded to %x (err=%v), want %x", back, err, prologue)
		}
	})
}
