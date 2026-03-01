package obfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"testing"
	"time"
)

// TestObfsDemo_MeasurableComparison is a demonstration test that shows
// the measurable difference between plain and obfuscated traffic.
// It prints hex dumps, entropy, and size comparisons.
func TestObfsDemo_MeasurableComparison(t *testing.T) {
	// === PLAIN SOCKS5 TRAFFIC (no obfuscation) ===
	socks5Greeting := []byte{0x05, 0x01, 0x00}                      // SOCKS5 greeting
	socks5Connect := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}           // CONNECT header
	socks5Connect = append(socks5Connect, []byte("example.com")...) // domain
	socks5Connect = append(socks5Connect, 0x01, 0xBB)               // port 443
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	t.Log("=== PLAIN TRAFFIC (без обфускации) ===")
	t.Logf("SOCKS5 Greeting  (%2d bytes): %s", len(socks5Greeting), hex.EncodeToString(socks5Greeting))
	t.Logf("SOCKS5 CONNECT   (%2d bytes): %s", len(socks5Connect), hex.EncodeToString(socks5Connect))
	t.Logf("HTTP Payload     (%2d bytes): %s", len(httpPayload), hex.EncodeToString(httpPayload))
	t.Logf("Plain Greeting entropy:  %.4f bits/byte", shannonEntropy(socks5Greeting))
	t.Logf("Plain CONNECT entropy:   %.4f bits/byte", shannonEntropy(socks5Connect))
	t.Logf("Plain HTTP entropy:      %.4f bits/byte", shannonEntropy(httpPayload))

	// === OBFUSCATED TRAFFIC ===
	psk := bytes.Repeat([]byte("K"), 32)
	cfg := Config{PSK: psk, MaxPadding: 128}

	// Capture wire bytes for each message
	wireGreeting := captureWireBytes(t, cfg, socks5Greeting)
	wireConnect := captureWireBytes(t, cfg, socks5Connect)
	wireHTTP := captureWireBytes(t, cfg, httpPayload)

	t.Log("")
	t.Log("=== OBFUSCATED TRAFFIC (с обфускацией AES-256-GCM + padding) ===")
	t.Logf("Obfs Greeting    (%2d bytes): %s", len(wireGreeting), hex.EncodeToString(wireGreeting))
	t.Logf("Obfs CONNECT     (%2d bytes): %s", len(wireConnect), hex.EncodeToString(wireConnect))
	t.Logf("Obfs HTTP        (%2d bytes): %s", len(wireHTTP), hex.EncodeToString(wireHTTP))
	t.Logf("Obfs Greeting entropy:   %.4f bits/byte", shannonEntropy(wireGreeting))
	t.Logf("Obfs CONNECT entropy:    %.4f bits/byte", shannonEntropy(wireConnect))
	t.Logf("Obfs HTTP entropy:       %.4f bits/byte", shannonEntropy(wireHTTP))

	// === SIZE COMPARISON ===
	t.Log("")
	t.Log("=== СРАВНЕНИЕ ===")
	t.Logf("Greeting: %d bytes plain → %d bytes obfs (overhead: +%d bytes, +%.0f%%)",
		len(socks5Greeting), len(wireGreeting),
		len(wireGreeting)-len(socks5Greeting),
		float64(len(wireGreeting)-len(socks5Greeting))/float64(len(socks5Greeting))*100)
	t.Logf("CONNECT:  %d bytes plain → %d bytes obfs (overhead: +%d bytes, +%.0f%%)",
		len(socks5Connect), len(wireConnect),
		len(wireConnect)-len(socks5Connect),
		float64(len(wireConnect)-len(socks5Connect))/float64(len(socks5Connect))*100)
	t.Logf("HTTP:     %d bytes plain → %d bytes obfs (overhead: +%d bytes, +%.0f%%)",
		len(httpPayload), len(wireHTTP),
		len(wireHTTP)-len(httpPayload),
		float64(len(wireHTTP)-len(httpPayload))/float64(len(httpPayload))*100)

	// === SIGNATURE CHECK ===
	t.Log("")
	t.Log("=== DPI SIGNATURE CHECK ===")
	containsSOCKS5 := bytes.Contains(wireGreeting, []byte{0x05, 0x01, 0x00})
	containsHTTP := bytes.Contains(wireHTTP, []byte("HTTP"))
	containsDomain := bytes.Contains(wireConnect, []byte("example.com"))
	t.Logf("SOCKS5 signature (0x050100) found on wire: %v", containsSOCKS5)
	t.Logf("HTTP keyword found on wire:                %v", containsHTTP)
	t.Logf("Domain 'example.com' found on wire:        %v", containsDomain)

	// === ASSERTIONS ===
	if containsSOCKS5 {
		t.Error("FAIL: SOCKS5 signature detected in obfuscated traffic!")
	}
	if containsHTTP {
		t.Error("FAIL: HTTP keyword detected in obfuscated traffic!")
	}
	if containsDomain {
		t.Error("FAIL: domain name detected in obfuscated traffic!")
	}

	// Entropy of truly random data approaches 8.0 bits/byte for large samples.
	// For short encrypted frames (42-188 bytes), 5.0+ is excellent and proves
	// the data is indistinguishable from noise. Plain SOCKS5 is ~1.5 bits/byte.
	for _, ent := range []struct {
		name string
		data []byte
	}{
		{"Greeting", wireGreeting},
		{"CONNECT", wireConnect},
		{"HTTP", wireHTTP},
	} {
		e := shannonEntropy(ent.data)
		if e < 5.0 {
			t.Errorf("FAIL: %s entropy %.4f is too low (expected > 5.0 for encrypted data)", ent.name, e)
		}
	}

	// Verify data is actually recoverable
	t.Log("")
	t.Log("=== INTEGRITY CHECK ===")
	verifyRoundTrip(t, cfg, socks5Greeting, "Greeting")
	verifyRoundTrip(t, cfg, socks5Connect, "CONNECT")
	verifyRoundTrip(t, cfg, httpPayload, "HTTP")
}

// captureWireBytes writes data through obfs and captures the raw bytes on the wire.
func captureWireBytes(t *testing.T, cfg Config, payload []byte) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	wireCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf) // read RAW bytes (no obfs wrapper)
		wireCh <- append([]byte{}, buf[:n]...)
	}()

	if _, err := obfsClient.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case wire := <-wireCh:
		return wire
	case <-time.After(2 * time.Second):
		t.Fatal("timeout capturing wire bytes")
		return nil
	}
}

// verifyRoundTrip confirms data survives encryption + decryption.
func verifyRoundTrip(t *testing.T, cfg Config, payload []byte, name string) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	obfsClient, _ := NewConn(clientConn, cfg)
	obfsServer, _ := NewConn(serverConn, cfg)

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		n, err := obfsServer.Read(buf)
		if err != nil {
			t.Errorf("%s roundtrip read error: %v", name, err)
		} else if !bytes.Equal(buf[:n], payload) {
			t.Errorf("%s roundtrip data mismatch", name)
		} else {
			t.Logf("%s: roundtrip OK (%d bytes in = %d bytes out)", name, len(payload), n)
		}
		close(done)
	}()

	obfsClient.Write(payload)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s roundtrip timeout", name)
	}
}

// shannonEntropy calculates the Shannon entropy of data in bits per byte.
// Truly random data ≈ 8.0, structured data (text, protocols) ≈ 3.0–5.0.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// Prevent unused import
var _ = fmt.Sprintf
