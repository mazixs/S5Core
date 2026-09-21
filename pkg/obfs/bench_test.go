package obfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Три уровня измерения. Без них "поменял буфер, вроде быстрее" - это мнение,
// а CLAUDE.md требует проверять правки буферов бенчмарками.
//
//  1. cipher   - только AEAD, пол потолка производительности;
//  2. framing  - кадрирование и запись на сокет, который ничего не делает;
//  3. endToEnd - полный путь Write -> сеть -> Read, то, что видит пользователь.
//
// Профили записи повторяют реальную подачу: 1400 - кадр по умолчанию, 4096 -
// типичный ответ, 32768 - буфер io.CopyBuffer из релея.
var benchSizes = []int{1400, 4096, 32768}

const benchPSK = "01234567890123456789012345678901"

// discardConn accepts writes and never blocks, isolating the framing cost from
// the network.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Close() error                     { return nil }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) LocalAddr() net.Addr              { return benchAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return benchAddr{} }

type benchAddr struct{}

func (benchAddr) Network() string { return "bench" }
func (benchAddr) String() string  { return "bench" }

func benchPayload(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// BenchmarkCipherOnly measures the AEAD alone: the floor nothing above it can
// beat. AES-GCM is what the current format uses; ChaCha20-Poly1305 is here
// because most routers have no AES-NI, where the ordering reverses - and plan
// task Ф5 has to choose between them.
func BenchmarkCipherOnly(b *testing.B) {
	block, err := aes.NewCipher([]byte(benchPSK))
	if err != nil {
		b.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	chacha, err := chacha20poly1305.New([]byte(benchPSK))
	if err != nil {
		b.Fatal(err)
	}

	for _, aead := range []struct {
		name string
		impl cipher.AEAD
	}{{"AESGCM", gcm}, {"ChaCha20Poly1305", chacha}} {
		for _, size := range benchSizes {
			b.Run(sizeName(aead.name, size), func(b *testing.B) {
				payload := benchPayload(size)
				nonce := make([]byte, aead.impl.NonceSize())
				dst := make([]byte, 0, size+aead.impl.Overhead())

				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					dst = aead.impl.Seal(dst[:0], nonce, payload, nil)
				}
			})
		}
	}
}

// BenchmarkFramingOnly measures everything obfs adds on write - padding,
// header, nonce, encryption - with the network removed.
func BenchmarkFramingOnly(b *testing.B) {
	for _, padding := range []int{0, 256} {
		for _, size := range benchSizes {
			b.Run(sizeName(paddingName(padding), size), func(b *testing.B) {
				c, err := NewClientConn(discardConn{}, Config{
					PSK:        []byte(benchPSK),
					MaxPadding: padding,
					MTU:        DefaultMTU,
				})
				if err != nil {
					b.Fatal(err)
				}
				payload := benchPayload(size)

				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if _, err := c.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkEndToEnd times confirmed delivery over loopback TCP. The receiver
// verifies each payload and acknowledges it before the next operation starts.
// It includes acknowledgement latency, but no SOCKS handshake, TLS or WAN.
func BenchmarkEndToEnd(b *testing.B) { benchmarkDelivery(b, false) }

// BenchmarkRoundTrip additionally returns and verifies the entire payload.
func BenchmarkRoundTrip(b *testing.B) { benchmarkDelivery(b, true) }

func benchmarkDelivery(b *testing.B, echo bool) {
	for _, size := range benchSizes {
		b.Run(sizeName("AESGCM", size), func(b *testing.B) {
			client, server := benchPair(b)
			_ = client.SetDeadline(time.Now().Add(5 * time.Minute))
			_ = server.SetDeadline(time.Now().Add(5 * time.Minute))
			payload := benchPayload(size)
			latencies := make([]time.Duration, 0, b.N)
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				buf := make([]byte, size)
				ack := []byte{1}
				for range b.N {
					if _, err := io.ReadFull(server, buf); err != nil {
						done <- err
						return
					}
					if !bytes.Equal(buf, payload) {
						done <- fmt.Errorf("receiver payload mismatch")
						return
					}
					reply := ack
					if echo {
						reply = buf
					}
					if _, err := server.Write(reply); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			back := make([]byte, 1)
			want := []byte{1}
			if echo {
				back = make([]byte, size)
				want = payload
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				start := time.Now()
				if _, err := client.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(client, back); err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(back, want) {
					b.Fatal("reply payload mismatch")
				}
				latencies = append(latencies, time.Since(start))
			}
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			reportPercentiles(b, latencies)
		})
	}
}

// benchPair returns two obfs connections over a real TCP socket pair. net.Pipe
// is unsuitable here: it is synchronous and has no buffers, so it measures
// goroutine scheduling rather than the transport.
func benchPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptCh <- accepted{c, err}
	}()

	rawClient, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	got := <-acceptCh
	if got.err != nil {
		b.Fatal(got.err)
	}

	cfg := Config{PSK: []byte(benchPSK), MaxPadding: 256, MTU: DefaultMTU}
	client, err = NewClientConn(rawClient, cfg)
	if err != nil {
		b.Fatal(err)
	}
	server, err = NewServerConn(got.conn, cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// reportPercentiles adds p50/p95/p99 to the benchmark output. Go reports the
// mean; a tail that appears once in a hundred frames is invisible in it and
// very visible to a user.
func reportPercentiles(b *testing.B, latencies []time.Duration) {
	b.Helper()
	if len(latencies) == 0 {
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pick := func(q float64) float64 {
		idx := int(float64(len(latencies)-1) * q)
		return float64(latencies[idx].Nanoseconds())
	}
	b.ReportMetric(pick(0.50), "p50-ns")
	b.ReportMetric(pick(0.95), "p95-ns")
	b.ReportMetric(pick(0.99), "p99-ns")
}

func sizeName(prefix string, size int) string {
	switch size {
	case 1400:
		return prefix + "/1400B"
	case 4096:
		return prefix + "/4KiB"
	case 32768:
		return prefix + "/32KiB"
	default:
		return prefix
	}
}

func paddingName(padding int) string {
	if padding == 0 {
		return "NoPadding"
	}
	return "Padding256"
}

// BenchmarkTunnelByCipher is the measurement plan task Ф5-5 turns on: the
// whole write path - padding, length mask, AEAD, header - once per cipher.
// BenchmarkCipherOnly above measures the AEAD in isolation; this one measures
// what a tunnel actually costs, which is the number a router's throughput
// follows.
//
// Run it twice. The second run is the aarch64 router the task names:
//
//	go test -run '^$' -bench TunnelByCipher ./pkg/obfs/
//	GODEBUG=cpu.aes=off go test -run '^$' -bench TunnelByCipher ./pkg/obfs/
//
// GODEBUG=cpu.aes=off disables the AES instructions for crypto/aes and for
// the detection in pkg/veil alike, so the second run times the same code a
// processor without AES executes. See docs/benchmarks/ciphers.md.
func BenchmarkTunnelByCipher(b *testing.B) {
	for _, c := range veil.Ciphers() {
		for _, size := range benchSizes {
			b.Run(sizeName(string(c), size), func(b *testing.B) {
				conn, err := NewClientConn(discardConn{}, Config{
					PSK:        []byte(benchPSK),
					MaxPadding: 256,
					MTU:        DefaultMTU,
					Scheme:     veil.Symmetric{Context: veil.Context{Cipher: c}},
				})
				if err != nil {
					b.Fatal(err)
				}
				payload := benchPayload(size)

				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := conn.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
