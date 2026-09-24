package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/pkg/s5server"
)

// FuzzAdviceFile writes arbitrary bytes as TRANSPORT_ADVICE_FILE and checks
// the reader against what advice_file.go and F19 promise:
//   - more than 4 KiB is refused, whatever it holds;
//   - otherwise the advice is the text trimmed of surrounding space, and it
//     is refused exactly when that text spans more than one line;
//   - what is read is what the server applies (resolveTransportAdvice), and
//     it parses exactly as the same line set in TRANSPORT_ADVICE would, so
//     the file passes the checks the variable does and no others.
func FuzzAdviceFile(f *testing.F) {
	f.Add([]byte("transport=ws min_frame=512 max_frame=2048\n"))
	f.Add([]byte("  obfs\t\r\n"))
	f.Add([]byte("ws\nobfs\n"))
	f.Add([]byte("ws\robfs"))
	f.Add([]byte("\n\n"))
	f.Add([]byte(strings.Repeat("x", maxAdviceFileBytes)))
	f.Add([]byte(strings.Repeat(" ", maxAdviceFileBytes+1)))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, content []byte) {
		path := filepath.Join(t.TempDir(), "advice")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		text, err := adviceFromFile(path)
		if len(content) > maxAdviceFileBytes {
			if err == nil {
				t.Fatalf("read an advice file of %d bytes", len(content))
			}
			return
		}
		trimmed := strings.TrimSpace(string(content))
		if multiline := strings.ContainsAny(trimmed, "\r\n"); multiline != (err != nil) {
			t.Fatalf("a file of %q gave err=%v", content, err)
		}
		if err != nil {
			if text != "" {
				t.Fatalf("a refusal returned %q", text)
			}
			return
		}
		if text != trimmed {
			t.Fatalf("read %q from %q", text, content)
		}

		cfg := params{TransportAdvice: "from the environment", TransportAdviceFile: path}
		if err := resolveTransportAdvice(&cfg); err != nil || cfg.TransportAdvice != text {
			t.Fatalf("the server applies %q (err=%v), the file says %q", cfg.TransportAdvice, err, text)
		}
		fromFile, ferr := s5server.ParseTransportAdvice(text)
		fromEnv, eerr := s5server.ParseTransportAdvice(string(content))
		if (ferr == nil) != (eerr == nil) || (fromFile == nil) != (fromEnv == nil) || (fromFile != nil && *fromFile != *fromEnv) {
			t.Fatalf("%q from the file gives %+v/%v, from the variable %+v/%v", content, fromFile, ferr, fromEnv, eerr)
		}
	})
}
