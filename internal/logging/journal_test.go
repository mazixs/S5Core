package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type memFile struct {
	mu   sync.Mutex
	fail bool
	// room, when positive, is how many bytes the next write takes before the
	// disk is full.
	room int
	buf  bytes.Buffer
}

func (f *memFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, errors.New("no space left on device")
	}
	if f.room > 0 && f.room < len(p) {
		n, _ := f.buf.Write(p[:f.room])
		f.room = 0
		f.fail = true
		return n, errors.New("no space left on device")
	}
	return f.buf.Write(p)
}

func (f *memFile) Close() error { return nil }

func (f *memFile) setFail(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

func (f *memFile) lines(t *testing.T) []map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(f.buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// Whatever a value holds, the line stays one JSON object on one line.
func TestAJournalLineSurvivesAnyValue(t *testing.T) {
	f := &memFile{}
	j := NewJournal(f, "0badb007")
	hostile := "a\"b\\c\nd\re\tf\x00g\x7fh\xffi j k"
	j.Write("INFO", "conn_end", func(l *Line) {
		l.Str("account", hostile)
		l.Int("up", -1)
		l.Uint("down", 1<<63)
		l.Bool("ok", true)
		l.Ms("dur_ms", 1500*time.Microsecond)
		l.Prefix("dst_net", netip.MustParsePrefix("2001:db8::/48"))
	})
	_ = j.Close()
	raw := f.buf.String()
	if strings.Count(raw, "\n") != 1 || strings.Contains(raw, " ") {
		t.Fatalf("the line broke: %q", raw)
	}
	lines := f.lines(t)
	l := lines[0]
	if l["event"] != "conn_end" || l["msg"] != "conn_end" || l["level"] != "INFO" || l["seq"] != float64(1) {
		t.Errorf("header: %v", l)
	}
	if _, err := time.Parse(time.RFC3339Nano, l["time"].(string)); err != nil {
		t.Errorf("time: %v", err)
	}
	if want := strings.ToValidUTF8(hostile, "�"); l["account"] != want {
		t.Errorf("account %q, want %q", l["account"], want)
	}
	if l["dur_ms"] != float64(1) || l["dst_net"] != "2001:db8::/48" || l["ok"] != true {
		t.Errorf("fields: %v", l)
	}
}

// A write that fails does not reach the caller and does not block it; the
// lines it carried are counted and announced by the next line that lands.
func TestAFailedWriteBecomesAGapNotAStall(t *testing.T) {
	f := &memFile{}
	j := NewJournal(f, "")
	j.Write("INFO", "conn_end", nil)
	j.Flush()
	f.setFail(true)
	done := make(chan struct{})
	go func() {
		for range 3 {
			j.Write("INFO", "conn_end", nil)
		}
		j.Flush()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a failing file blocked the writer")
	}
	if j.Dropped() != 3 {
		t.Fatalf("dropped %d, want 3", j.Dropped())
	}
	f.setFail(false)
	j.Write("INFO", "conn_end", nil)
	_ = j.Close()

	lines := f.lines(t)
	if len(lines) != 3 {
		t.Fatalf("%d lines: %v", len(lines), lines)
	}
	if lines[1]["event"] != "log_gap" || lines[1]["dropped"] != float64(3) || lines[1]["level"] != "WARN" {
		t.Errorf("gap marker: %v", lines[1])
	}
	// seq counts the lost lines too, so the gap is visible in it.
	if lines[0]["seq"] != float64(1) || lines[1]["seq"] != float64(5) || lines[2]["seq"] != float64(6) {
		t.Errorf("seq: %v %v %v", lines[0]["seq"], lines[1]["seq"], lines[2]["seq"])
	}
	if j.Lines(0) != 2 || j.Lines(1) != 1 {
		t.Errorf("lines info %d warn %d", j.Lines(0), j.Lines(1))
	}
	j.Write("INFO", "late", nil)
	if j.Dropped() != 4 {
		t.Error("a line after Close is not counted as dropped")
	}
}

// A write that stops inside a line costs that line only: the lines before it
// are counted as written, and the marker after it starts on a line of its
// own, so everything from the marker on parses.
func TestAPartialWriteKeepsTheLinesAfterItWhole(t *testing.T) {
	f := &memFile{}
	j := NewJournal(f, "")
	j.Write("INFO", "first", nil)
	j.Flush()
	j.Write("WARN", "second", nil)
	j.mu.Lock()
	second := len(j.buf)
	j.mu.Unlock()
	j.Write("INFO", "third", nil)
	f.mu.Lock()
	f.room = second + 10
	f.mu.Unlock()
	j.Flush()
	if j.Dropped() != 1 || j.Lines(0) != 1 || j.Lines(1) != 1 {
		t.Fatalf("dropped %d, info %d, warn %d", j.Dropped(), j.Lines(0), j.Lines(1))
	}
	f.setFail(false)
	j.Write("INFO", "fourth", nil)
	_ = j.Close()

	raw := strings.Split(strings.TrimSuffix(f.buf.String(), "\n"), "\n")
	if len(raw) != 5 {
		t.Fatalf("%d lines: %q", len(raw), raw)
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw[2]), &m) == nil {
		t.Errorf("the torn line parsed: %q", raw[2])
	}
	want := []string{"first", "second", "", "log_gap", "fourth"}
	for i, l := range raw {
		if want[i] == "" {
			continue
		}
		m = nil
		if err := json.Unmarshal([]byte(l), &m); err != nil || m["event"] != want[i] {
			t.Errorf("line %d %q: %v", i, l, err)
		}
		if want[i] == "log_gap" && m["dropped"] != float64(1) {
			t.Errorf("gap marker %v", m)
		}
	}
}

// A torn line at Close is ended, so the next process appends on a new line.
func TestCloseEndsATornLine(t *testing.T) {
	f := &memFile{}
	j := NewJournal(f, "")
	j.Write("INFO", "first", nil)
	f.mu.Lock()
	f.room = 10
	f.mu.Unlock()
	j.Flush()
	f.setFail(false)
	_ = j.Close()
	if got := f.buf.String(); len(got) != 11 || !strings.HasSuffix(got, "\n") {
		t.Errorf("file %q", got)
	}
}

// Lines wait in the buffer one FlushInterval at most.
func TestTheJournalFlushesOnItsOwn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &memFile{}
		j := NewJournal(f, "")
		defer j.Close()
		j.Write("INFO", "conn_end", nil)
		time.Sleep(FlushInterval - time.Millisecond)
		synctest.Wait()
		if n := len(f.lines(t)); n != 0 {
			t.Fatalf("%d lines before the interval", n)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if n := len(f.lines(t)); n != 1 {
			t.Fatalf("%d lines after the interval", n)
		}
	})
}

func TestLastEventReadsTheTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	if got := LastEvent(path); got != "" {
		t.Errorf("missing file: %q", got)
	}
	body := strings.Repeat(`{"event":"conn_end","pad":"`+strings.Repeat("x", 100)+`"}`+"\n", 200) +
		`{"time":"t","event":"process_stop","seq":201}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LastEvent(path); got != "process_stop" {
		t.Errorf("got %q", got)
	}
}

func TestTheServiceLogCountsItsLines(t *testing.T) {
	before := ServiceLines(2)
	logger := NewTee(io.Discard, io.Discard, slog.LevelWarn)
	logger.Warn("one")
	logger.Warn("two")
	if got := ServiceLines(2) - before; got != 2 {
		t.Errorf("counted %d warn lines, want 2", got)
	}
}

// The console copy is short text at its own level; the file keeps JSON at
// the shared one.
func TestTheTeeSplitsFileAndConsole(t *testing.T) {
	var file, console bytes.Buffer
	logger := NewTee(&file, &console, slog.LevelWarn)
	logger.Info("quiet", "k", 1)
	logger.Warn("loud", "k", 2)
	if strings.Contains(console.String(), "quiet") || !strings.Contains(console.String(), "msg=loud") {
		t.Errorf("console: %q", console.String())
	}
	if !strings.Contains(file.String(), `"msg":"quiet"`) || !strings.Contains(file.String(), `"msg":"loud"`) {
		t.Errorf("file: %q", file.String())
	}
}

func BenchmarkJournalLine(b *testing.B) {
	j := NewJournal(&memFile{}, "")
	defer j.Close()
	b.ReportAllocs()
	for b.Loop() {
		j.Write("INFO", "conn_end", func(l *Line) {
			l.Str("conn", "a1b2c3d4e5f6")
			l.Str("account", "linux-de2")
			l.Str("auth", "key")
			l.Str("transport", "obfs")
			l.Str("client", "2.3.0-rc6")
			l.Str("cmd", "connect")
			l.Prefix("dst_net", netip.MustParsePrefix("172.217.132.0/24"))
			l.Int("dst_port", 443)
			l.Str("dst_kind", "ip")
			l.Str("result", "ok")
			l.Str("closed_by", "client")
			l.Int("dial_ms", 163)
			l.Int("dial_tries", 2)
			l.Int("dial_backups", 1)
			l.Int("first_byte_ms", 41)
			l.Int("dur_ms", 95321)
			l.Int("up", 12345)
			l.Int("down", 9876543)
		})
	}
}
