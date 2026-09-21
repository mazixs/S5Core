package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

// Plan task Ф5-5 asks for ChaCha20-Poly1305 "automatically on processors
// without hardware AES (aarch64 routers)". These tests hold the two halves
// of that sentence: the choice follows the processor, and the choice is
// carried without changing anything an observer can see.

func TestTheCipherFollowsTheProcessor(t *testing.T) {
	// The check is written against the same detection the code uses rather
	// than against a hard-coded expectation, because the test runs on
	// whatever machine CI happens to give it - including, under
	// GODEBUG=cpu.aes=off, one that reports no AES at all.
	hardware := cpu.X86.HasAES || cpu.ARM64.HasAES || cpu.S390X.HasAES || cpu.PPC64.IsPOWER8

	want := CipherChaCha
	if hardware {
		want = CipherAES
	}
	if got := PreferredCipher(); got != want {
		t.Errorf("a processor with hardware AES = %v prefers %q, want %q", hardware, got, want)
	}
}

// The frame layout must not depend on the cipher: the length field, the
// nonce and the tag are the same sizes either way, so a censor cannot tell
// the two apart by counting bytes. This is what makes the choice free.
func TestBothCiphersProduceTheSameFrameShape(t *testing.T) {
	psk := testPSK()
	secret := []byte("a shared salt, thirty-two bytes!")

	var sizes []int
	for _, c := range Ciphers() {
		s := derive(t, psk, secret, Context{Cipher: c}, RoleClient)
		if got := s.Send.Data.NonceSize(); got != 12 {
			t.Errorf("cipher %q has a %d-byte nonce, the format reserves 12", c, got)
		}
		if got := s.Send.Data.Overhead(); got != 16 {
			t.Errorf("cipher %q has a %d-byte tag, the format reserves 16", c, got)
		}
		nonce := make([]byte, s.Send.Data.NonceSize())
		sizes = append(sizes, len(s.Send.Data.Seal(nil, nonce, make([]byte, 100), nil)))
	}
	for i := range sizes {
		if sizes[i] != sizes[0] {
			t.Errorf("cipher %q seals 100 bytes into %d, cipher %q into %d",
				Ciphers()[i], sizes[i], Ciphers()[0], sizes[0])
		}
	}
}

func TestTheTwoCiphersAreDifferentKeys(t *testing.T) {
	psk := testPSK()
	secret := []byte("a shared salt, thirty-two bytes!")

	aesKeys := derive(t, psk, secret, Context{Cipher: CipherAES}, RoleClient)
	chaKeys := derive(t, psk, secret, Context{Cipher: CipherChaCha}, RoleClient)

	if bytes.Equal(mask(aesKeys.Send), mask(chaKeys.Send)) {
		t.Error("the two ciphers produce the same length mask")
	}

	// And the default is AES, so a deployment that never named a cipher
	// keeps deriving exactly what it derived before this task.
	plain := derive(t, psk, secret, Context{}, RoleClient)
	if !bytes.Equal(seal(plain.Send), seal(aesKeys.Send)) {
		t.Error("the unnamed cipher is not the AES one")
	}
}

func TestAnUnknownCipherIsRefused(t *testing.T) {
	if _, err := Derive(testPSK(), []byte("a shared salt, thirty-two bytes!"),
		Context{Cipher: "rot13"}, RoleClient); err == nil {
		t.Error("Derive accepted a cipher it cannot build")
	}
}

// The length mask is the one stateful piece: a ChaCha mask keeps a cipher
// across frames and rebuilds it when the counter crosses 2^32. Both masks
// must nevertheless behave like a pure function of the counter.
func TestALengthMaskIsAFunctionOfItsCounter(t *testing.T) {
	key := bytes.Repeat([]byte("m"), 32)

	for _, c := range Ciphers() {
		t.Run(string(c), func(t *testing.T) {
			first, err := newLengthMask(c, key)
			if err != nil {
				t.Fatal(err)
			}
			second, err := newLengthMask(c, key)
			if err != nil {
				t.Fatal(err)
			}

			// Counters chosen to cross the 2^32 boundary the ChaCha mask
			// rebuilds at, and to go back down again: a mask that cached
			// the wrong thing fails on the way back.
			counters := []uint64{0, 1, 2, 1 << 31, 1<<32 - 1, 1 << 32, 1<<32 + 1, 5, 1 << 33}
			seen := make(map[uint16]uint64, len(counters))
			for _, n := range counters {
				a := first.Mask(n)
				if b := second.Mask(n); a != b {
					t.Errorf("counter %d masks to %04x on one mask and %04x on another", n, a, b)
				}
				if prev, dup := seen[a]; dup {
					t.Errorf("counters %d and %d mask to the same %04x", prev, n, a)
				}
				seen[a] = n
			}
		})
	}
}

// The benchmark plan task Ф5-5 asks for. It is meant to be run twice:
//
//	go test -run '^$' -bench Cipher ./pkg/veil/
//	GODEBUG=cpu.aes=off go test -run '^$' -bench Cipher ./pkg/veil/
//
// The second run is the aarch64 router the task names. GODEBUG=cpu.aes=off
// turns off the AES instructions for both crypto/aes and the detection this
// package uses, so the numbers are real timings of the code path a processor
// without AES takes. See docs/benchmarks/ciphers.md for the measurements.
func BenchmarkCipherSeal(b *testing.B) {
	benchCipher(b, func(b *testing.B, k Keys, payload []byte) {
		nonce := make([]byte, k.Data.NonceSize())
		dst := make([]byte, 0, len(payload)+k.Data.Overhead())
		for i := 0; b.Loop(); i++ {
			nonce[0] = byte(i)
			_ = k.Data.Seal(dst[:0], nonce, payload, nil)
		}
	})
}

func BenchmarkCipherOpen(b *testing.B) {
	benchCipher(b, func(b *testing.B, k Keys, payload []byte) {
		nonce := make([]byte, k.Data.NonceSize())
		sealed := k.Data.Seal(nil, nonce, payload, nil)
		dst := make([]byte, 0, len(payload))
		for b.Loop() {
			if _, err := k.Data.Open(dst[:0], nonce, sealed, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// The length mask runs once per frame whatever the frame carries, so on
// small frames it is a real share of the cost, not a rounding error.
func BenchmarkCipherLengthMask(b *testing.B) {
	for _, c := range Ciphers() {
		b.Run(string(c), func(b *testing.B) {
			mask, err := newLengthMask(c, bytes.Repeat([]byte("m"), 32))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				_ = mask.Mask(uint64(i))
			}
		})
	}
}

// benchCipher runs one measurement across both ciphers and a small and a
// large frame. The small size is a shell keystroke inside the tunnel, the
// large one is a full default-MTU frame.
func benchCipher(b *testing.B, run func(b *testing.B, k Keys, payload []byte)) {
	psk := testPSK()
	secret := make([]byte, SaltSize)
	if _, err := rand.Read(secret); err != nil {
		b.Fatal(err)
	}

	for _, size := range []int{64, 1400} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			b.Fatal(err)
		}
		for _, c := range Ciphers() {
			b.Run(fmt.Sprintf("%s/%d", c, size), func(b *testing.B) {
				session, err := Derive(psk, secret, Context{Cipher: c}, RoleClient)
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				run(b, session.Send, payload)
			})
		}
	}
}
