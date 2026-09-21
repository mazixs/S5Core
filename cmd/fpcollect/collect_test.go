package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/utls"
)

// The collector is the one piece of level 4 that runs on the far side of a
// real path, so a bug in it looks exactly like a finding: a fingerprint that
// does not match the preset reads as "something on the path rewrote the
// handshake". This test closes the loop locally - client, wire, parser,
// report - so that when the same check is run across a network, a mismatch
// means the network.
func TestTheCollectorReportsWhatTheClientSent(t *testing.T) {
	for _, tc := range []struct {
		fingerprint string
		ja4         string
		grease      bool
	}{
		{utls.FPChrome, "t13d1516h2_8daaf6152771_d8a2da3f94cd", true},
		{utls.FPFirefox, "t13d1715h2_5b57614c22b0_5c2c66f702b0", false},
		{utls.FPDefaultGo, "t13d031000_55b375c5d22e_e7c285222651", false},
	} {
		t.Run(tc.fingerprint, func(t *testing.T) {
			rep := collectOnce(t, tc.fingerprint)
			if rep.JA4 != tc.ja4 {
				t.Errorf("JA4\n  want %s\n  got  %s", tc.ja4, rep.JA4)
			}
			if rep.GREASE != tc.grease {
				t.Errorf("GREASE: want %v, got %v", tc.grease, rep.GREASE)
			}
			if rep.SNI != "collector.test" {
				t.Errorf("SNI: want collector.test, got %q", rep.SNI)
			}
			if rep.JA3 == "" || rep.JA3String == "" {
				t.Error("the report carries no JA3")
			}
		})
	}
}

// A client offering ALPN that the server does not answer is worth saying out
// loud: an ordinary web server picks one, so the silence is a difference
// between this deployment and the traffic it is imitating.
func TestAnUnansweredALPNOfferIsCalledOut(t *testing.T) {
	withALPN := collectOnce(t, utls.FPChrome)
	if withALPN.Note != "" {
		t.Errorf("with ALPN configured the report should carry no note, got %q", withALPN.Note)
	}
	if withALPN.ALPNNegotiated != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1", withALPN.ALPNNegotiated)
	}

	silent := collectOnceWithALPN(t, utls.FPChrome, nil)
	if silent.Note == "" {
		t.Error("a server that answered no ALPN at all produced no note")
	}
	if silent.ALPNNegotiated != "" {
		t.Errorf("negotiated %q, want nothing", silent.ALPNNegotiated)
	}
}

func collectOnce(t *testing.T, fingerprint string) report {
	t.Helper()
	return collectOnceWithALPN(t, fingerprint, []string{"http/1.1"})
}

func collectOnceWithALPN(t *testing.T, fingerprint string, alpn []string) report {
	t.Helper()

	cert, err := loadOrCreateCert("", "", "collector.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: alpn}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		serve(conn, cfg, true)
	}()

	// The collector signs its own certificate, so the client is given that
	// certificate as its only root: the dial still verifies, it simply
	// verifies against the collector rather than against the world.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := utls.DialContext(ctx, "tcp", ln.Addr().String(), utls.Options{
		ServerName:  "collector.test",
		Fingerprint: fingerprint,
		RootCAs:     roots,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.NewRequest(http.MethodGet, "https://collector.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rep report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rep
}
