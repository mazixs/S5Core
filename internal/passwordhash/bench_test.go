package passwordhash

import (
	"testing"
)

// Argon2id is deliberately expensive, and on this code path it runs once per
// SOCKS5 login - not once per user session, once per TCP connection. These
// benchmarks give the ceiling: how many logins a machine can verify per
// second, and how much memory the parallel case needs at 64 MiB per call.
//
//	go test -bench=Argon2id -benchtime=20x ./internal/passwordhash/
//
// BenchmarkArgon2idVerify is the single-core cost. BenchmarkArgon2idVerifyParallel
// saturates every core, which is the shape of a burst of browser connections.

const benchPassword = "load-password-1234"

func benchHash(b *testing.B) string {
	b.Helper()
	h, err := Hash(benchPassword)
	if err != nil {
		b.Fatalf("hash: %v", err)
	}
	return h
}

func BenchmarkArgon2idVerify(b *testing.B) {
	hash := benchHash(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := Verify(benchPassword, hash)
		if err != nil || !ok {
			b.Fatalf("verify: ok=%v err=%v", ok, err)
		}
	}
}

func BenchmarkArgon2idVerifyParallel(b *testing.B) {
	hash := benchHash(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ok, err := Verify(benchPassword, hash)
			if err != nil || !ok {
				b.Fatalf("verify: ok=%v err=%v", ok, err)
			}
		}
	})
}
