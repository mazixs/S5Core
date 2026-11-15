package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/diagnostics"
	"github.com/mazixs/S5Core/internal/logging"
)

// With LOG_FILE and S5_DIAGNOSTICS_DIR both set, the recorder's first line -
// that it is on, or why it is off - is written once run has moved the logger
// to the file. Started earlier, it went to the console the process began on.
// run also stops the recorder before it returns.
func TestTheLatencyRecorderReportsToTheLogFile(t *testing.T) {
	for _, c := range []struct {
		name      string
		dir       func(t *testing.T) string
		line      string
		onConsole bool // an error also reaches the console, as the tee says
	}{
		{"on", func(t *testing.T) string { return filepath.Join(t.TempDir(), "diag") }, "Latency diagnostics are on", false},
		{"off", func(t *testing.T) string {
			notADir := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(notADir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return notADir
		}, "Latency diagnostics are off", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			restoreStdLog(t)
			original := slog.Default()
			t.Cleanup(func() { slog.SetDefault(original) })

			// The console is a file, and the logger of the process starts on
			// it, as main sets it up before run.
			console, err := os.CreateTemp(t.TempDir(), "console")
			if err != nil {
				t.Fatal(err)
			}
			stdout := os.Stdout
			os.Stdout = console
			t.Cleanup(func() {
				os.Stdout = stdout
				_ = console.Close()
			})
			slog.SetDefault(logging.New(os.Stdout))

			logFile := filepath.Join(t.TempDir(), "s5client.log")
			t.Setenv("S5_DIAGNOSTICS_DIR", c.dir(t))
			var cfg clientParams
			if err := env.ParseWithOptions(&cfg, env.Options{Environment: map[string]string{
				"SERVER_ADDR":        "198.51.100.7:1443",
				"OBFS_PSK":           testPSK32,
				"CLIENT_LISTEN_ADDR": "127.0.0.1:0",
				"LOG_FILE":           logFile,
			}}); err != nil {
				t.Fatal(err)
			}
			if !prepare(&cfg) {
				t.Fatal("the test configuration is refused")
			}

			ctx, cancel := context.WithCancel(context.Background())
			var runErr error
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				runErr = run(ctx, cfg)
			}()
			stopRun := sync.OnceValue(func() error {
				cancel()
				select {
				case <-finished:
					return runErr
				case <-time.After(10 * time.Second):
					return errors.New("run did not return")
				}
			})
			t.Cleanup(func() { _ = stopRun() })

			// The line is written by the recorder's own goroutine: wait for it
			// in the file, up to a deadline.
			want := `"msg":"` + c.line + `"`
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				data, _ := os.ReadFile(logFile)
				if strings.Contains(string(data), want) {
					break
				}
				select {
				case <-finished:
					t.Fatalf("run ended with %v before %q reached LOG_FILE:\n%s", runErr, c.line, data)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("%q did not reach LOG_FILE:\n%s", c.line, data)
				}
			}
			if err := stopRun(); err != nil {
				t.Fatal(err)
			}

			if got, _ := os.ReadFile(console.Name()); !c.onConsole && strings.Contains(string(got), c.line) {
				t.Errorf("%q reached the console:\n%s", c.line, got)
			}
			probe, _ := tcpPair(t)
			if diagnostics.ObserveConn(probe, "probe", "tcp") != probe {
				t.Error("run left the latency recorder running")
			}
		})
	}
}
