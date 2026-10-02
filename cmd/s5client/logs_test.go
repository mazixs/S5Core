package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// Each run gets a file of its own, the last ones are kept in archive/, and a
// run that ended without its closing line is named by the next one.
func TestTheLogFileKeepsTheLastRuns(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	dir := t.TempDir()
	cfg := clientParams{LogFile: filepath.Join(dir, "s5client.log"), LogKeep: 2, LogMaxSizeMB: 10, LogConsoleLevel: "warn"}

	var unclean []bool
	for run := range 4 {
		var console bytes.Buffer
		file, prev, err := openLogFile(cfg, &console)
		if err != nil {
			t.Fatal(err)
		}
		unclean = append(unclean, prev)
		slog.Info("S5Client starting", "event", eventStart, "run", run)
		slog.Warn("Tunnel setup timed out", "run", run)
		if run != 2 {
			slog.Info("S5Client stopped", "event", eventStop)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(console.String(), "S5Client") || !strings.Contains(console.String(), "msg=\"Tunnel setup timed out\"") {
			t.Errorf("console of run %d: %q", run, console.String())
		}
	}
	if want := []bool{false, false, false, true}; !equalBools(unclean, want) {
		t.Errorf("prev_unclean by run %v, want %v", unclean, want)
	}
	runs, err := os.ReadDir(filepath.Join(dir, "archive"))
	if err != nil || len(runs) != 2 {
		t.Fatalf("archive %v, %v", runs, err)
	}
	live, _ := os.ReadFile(cfg.LogFile)
	for _, line := range strings.Split(strings.TrimSpace(string(live)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if run, ok := m["run"]; ok && run != float64(3) {
			t.Errorf("the live file holds another run: %q", line)
		}
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestABadLogSettingStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []clientParams{
		{LogFile: filepath.Join(dir, "a.log"), LogConsoleLevel: "loud"},
		{LogFile: filepath.Join(dir, "b.log"), LogConsoleLevel: "warn", LogKeep: -1},
		{LogFile: dir, LogConsoleLevel: "warn"},
	} {
		if _, _, err := openLogFile(cfg, io.Discard); err == nil {
			t.Errorf("%+v was accepted", cfg)
		}
	}
	if f, _, err := openLogFile(clientParams{}, io.Discard); f != nil || err != nil {
		t.Error("no LOG_FILE still opened a file")
	}
}

// On Windows a failed rename of the last run's file is a second copy of the
// client holding it open, and the error says so.
func TestAnOpenLogFileOnWindowsIsNamed(t *testing.T) {
	rename := fmt.Errorf("logging: %w", &os.LinkError{Op: "rename", Old: "s5client.log", New: "archive/x.log", Err: errors.New("sharing violation")})
	if got := explainLogFileError("windows", rename).Error(); !strings.Contains(got, "another running copy") || !strings.Contains(got, "sharing violation") {
		t.Errorf("windows: %q", got)
	}
	if got := explainLogFileError("linux", rename); got.Error() != rename.Error() {
		t.Errorf("linux: %q", got)
	}
	other := errors.New("permission denied")
	if got := explainLogFileError("windows", other); got.Error() != other.Error() {
		t.Errorf("not a rename: %q", got)
	}
}

func TestWhoEndedARelay(t *testing.T) {
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	reset := &net.OpError{Op: "read", Err: syscall.ECONNRESET}
	for _, c := range []struct {
		first copyResult
		up    bool
		want  string
	}{
		{copyResult{}, true, closedByApp},
		{copyResult{}, false, closedByServer},
		{copyResult{err: timeout, reading: false}, false, closedByTimeout},
		{copyResult{err: reset, reading: true}, true, closedByApp},
		{copyResult{err: reset, reading: false}, true, closedByTunnelError},
		{copyResult{err: reset, reading: true}, false, closedByTunnelError},
		{copyResult{err: reset, reading: false}, false, closedByApp},
	} {
		if got := relayClosedBy(c.first, c.up); got != c.want {
			t.Errorf("%+v up=%v: %q, want %q", c.first, c.up, got, c.want)
		}
	}
}

// relayCopy tells a failed read from a failed write.
func TestARelayDirectionSaysWhichSideFailed(t *testing.T) {
	broken := errors.New("broken")
	r := relayCopy(io.Discard, io.MultiReader(strings.NewReader("abc"), errReader{broken}))
	if r.n != 3 || !errors.Is(r.err, broken) || !r.reading {
		t.Errorf("read failure: %+v", r)
	}
	r = relayCopy(errWriter{broken}, strings.NewReader("abc"))
	if !errors.Is(r.err, broken) || r.reading {
		t.Errorf("write failure: %+v", r)
	}
	r = relayCopy(io.Discard, strings.NewReader("abcd"))
	if r.n != 4 || r.err != nil {
		t.Errorf("clean end: %+v", r)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

// One line per relayed connection, written when it ends, under the id the
// server gives the same connection.
func TestATunnelEndsInOneLineThatNamesItLikeTheServer(t *testing.T) {
	const psk = "01234567890123456789012345678901"
	buf := &syncBuffer{}
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))

	serverID := make(chan string, 1)
	addr, done := startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			t.Errorf("greeting: %v", err)
			return
		}
		req := make([]byte, len(clientRequest()))
		if _, err := io.ReadFull(conn, req); err != nil {
			t.Errorf("request: %v", err)
			return
		}
		serverID <- obfs.LogIDOf(conn)
		// The reply and the first bytes of the target in one write, as a
		// fast target makes them.
		_, _ = conn.Write([]byte{0x05, 0x00})
		_, _ = conn.Write(append([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, "hi"...))
		bye := make([]byte, 3)
		if _, err := io.ReadFull(conn, bye); err != nil {
			t.Errorf("bye: %v", err)
		}
		_, _ = conn.Write([]byte("hello"))
		// The target hangs up.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, conn)
	})
	defer done()

	// TCP, not a pipe: the application still sends after the target has
	// hung up, which needs a half-close.
	app, local := tcpPair(t)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handleClient(local, clientParams{ServerAddr: addr, PSK: psk, MTU: 1400}, newDomainMatcher(nil))
	}()
	go func() {
		_, _ = app.Write([]byte{0x05, 0x01, 0x00})
		_, _ = app.Write(clientRequest())
	}()
	var reply [2 + 10]byte
	if _, err := io.ReadFull(app, reply[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(app); err != nil || string(got) != "hihello" {
		t.Fatalf("payload %q, %v", got, err)
	}
	_ = app.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not end")
	}

	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "TCP Tunnel closed" {
			if line != nil {
				t.Fatal("two closing lines for one connection")
			}
			line = m
		}
	}
	if line == nil {
		t.Fatalf("no closing line in %s", buf.String())
	}
	if id := <-serverID; id == "" || line["conn"] != id {
		t.Errorf("client conn %v, server %q", line["conn"], id)
	}
	if line["dest"] != "example.com" || line["down"] != float64(7) || line["closed_by"] != closedByServer || line["level"] != "INFO" {
		t.Errorf("line %v", line)
	}
	if up := line["up"].(float64); up != 3 {
		t.Errorf("up %v", up)
	}
	for _, k := range []string{"setup_ms", "dur_ms", "transport", "server"} {
		if _, ok := line[k]; !ok {
			t.Errorf("no %s in %v", k, line)
		}
	}
}

// The minute line is written for a minute that had something in it, and
// counts that minute only.
func TestTheMinuteSummaryIsWrittenOnlyForABusyMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := &syncBuffer{}
		original := slog.Default()
		defer slog.SetDefault(original)
		slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
		var m minuteCounts
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.run(ctx, "0badb007")

		m.tcpClosed(closedByApp)
		m.tcpClosed(closedByApp)
		m.tcpClosed(closedByTimeout)
		m.setupFailed(phaseGreeting)
		m.setupFailed("")
		m.udp.Add(1)
		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Fatalf("lines %q", lines)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
			t.Fatal(err)
		}
		if got["event"] != eventMinute || got["boot"] != "0badb007" || got["tcp_closed"] != float64(3) ||
			got["setup_failed"] != float64(2) || got["udp_closed"] != float64(1) {
			t.Errorf("line %v", got)
		}
		by := got["closed_by"].(map[string]any)
		if by["app"] != float64(2) || by["timeout"] != float64(1) || len(by) != 2 {
			t.Errorf("closed_by %v", by)
		}
		phases := got["failed_phase"].(map[string]any)
		if phases["greeting"] != float64(1) || phases["other"] != float64(1) {
			t.Errorf("failed_phase %v", phases)
		}

		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if n := strings.Count(strings.TrimSpace(buf.String()), "\n"); n != 0 {
			t.Errorf("an idle minute wrote a line: %s", buf.String())
		}
	})
}

func TestTheLogNamesAnAddressTarget(t *testing.T) {
	cases := []struct {
		req  []byte
		fqdn string
		want string
	}{
		{[]byte{5, 1, 0, 3, 11}, "example.com", "example.com"},
		{[]byte{5, 1, 0, 1, 192, 0, 2, 7, 1, 187}, "", "192.0.2.7"},
		{append([]byte{5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8}, append(make([]byte, 11), 1, 0, 80)...), "", "2001:db8::1"},
		{[]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, "", ""},
	}
	for _, c := range cases {
		if got := logDest(c.req, c.fqdn); got != c.want {
			t.Errorf("logDest(%v, %q) = %q, want %q", c.req, c.fqdn, got, c.want)
		}
	}
}
