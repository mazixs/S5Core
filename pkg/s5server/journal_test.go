package s5server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// journalFields is every field a journal line may carry. A field outside it
// fails the test: the journal is an exception to the observability policy,
// and the exception is this list.
var journalFields = map[string]bool{
	"time": true, "level": true, "msg": true, "event": true, "seq": true,
	"boot": true, "version": true, "go_version": true, "pid": true, "transports": true,
	"session_log": true, "prev_unclean": true, "uptime_s": true, "conns": true, "open": true,
	"reload": true, "failed": true, "dropped": true,
	"conn": true, "account": true, "auth": true, "transport": true, "client": true, "cmd": true,
	"dst_net": true, "dst_port": true, "dst_kind": true, "result": true, "stage": true,
	"closed_by": true, "reason": true, "dial_ms": true, "dial_tries": true, "dial_backups": true,
	"dial_backup_won": true, "first_byte_ms": true, "dur_ms": true, "up": true, "down": true,
	"dgram_up": true, "dgram_down": true, "rotations": true, "answered": true,
	"assocs": true,
}

func readJournal(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q is not JSON: %v", sc.Text(), err)
		}
		for k := range m {
			if !journalFields[k] {
				t.Errorf("field %q is not in the journal's closed list: %s", k, sc.Text())
			}
		}
		lines = append(lines, m)
	}
	return lines
}

func eventsOf(lines []map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["event"] == event {
			out = append(out, l)
		}
	}
	return out
}

// One server, every way in: a member by key, a password through the tunnel,
// a wrong password, a plain-listener CONNECT. After Stop the journal holds a
// start, a line per connection with an id the client computes too, a stop -
// and nothing a secret could be read from.
func TestTheJournalWritesOneLinePerConnectionAndNoSecrets(t *testing.T) {
	key := randomMemberKey(t)
	echo := startEchoServer(t)
	path := filepath.Join(t.TempDir(), "logs", "sessions.jsonl")
	cfg := Config{
		ListenIP:       "127.0.0.1",
		Port:           reservePort(t),
		ObfsEnabled:    true,
		ObfsPort:       reservePort(t),
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 256,
		ObfsMTU:        1400,
		RequireAuth:    true,
		UsersFile:      memberUsersFile(t, key),
		SessionLog:     SessionLogAll,
		SessionLogFile: path,
	}
	srv := startServer(t, cfg)

	var ids []string
	member := dialMember(t, cfg.ObfsPort, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
	if err := connectAsMember(member, echo); err != nil {
		t.Fatal(err)
	}
	ids = append(ids, obfs.LogIDOf(member))
	_ = member.Close()

	shared := dialMember(t, cfg.ObfsPort, &veil.Clocked{})
	if err := socks5Connect(shared, "bob", "secret2", echo); err != nil {
		t.Fatal(err)
	}
	ids = append(ids, obfs.LogIDOf(shared))
	_ = shared.Close()

	wrong := dialMember(t, cfg.ObfsPort, &veil.Clocked{})
	if err := socks5Connect(wrong, "mallory-typed-this", "hunter2-password", echo); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	ids = append(ids, obfs.LogIDOf(wrong))
	_ = wrong.Close()

	plain, err := net.Dial("tcp", "127.0.0.1:"+cfg.Port)
	if err != nil {
		t.Fatal(err)
	}
	if err := socks5Connect(plain, "bob", "secret2", echo); err != nil {
		t.Fatal(err)
	}
	_ = plain.Close()

	// A probe that never speaks SOCKS5 is not a session.
	probe, err := net.Dial("tcp", "127.0.0.1:"+cfg.Port)
	if err != nil {
		t.Fatal(err)
	}
	_ = probe.Close()

	deadline := time.Now().Add(5 * time.Second)
	for srv.connsEnded.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the journal is %v, want 0600", mode)
	}

	raw, _ := os.ReadFile(path)
	for _, secret := range []string{testPSK, base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key),
		"secret2", "hunter2-password", "mallory-typed-this", "the password nobody should need", "127.0.0.1"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the journal holds %q", secret)
		}
	}

	lines := readJournal(t, path)
	if len(lines) == 0 || lines[0]["event"] != "process_start" || lines[len(lines)-1]["event"] != "process_stop" {
		t.Fatalf("the journal does not start and stop with the process: %v", lines)
	}
	if lines[0]["prev_unclean"] != false {
		t.Errorf("a fresh journal says the previous process was unclean")
	}
	for i, l := range lines {
		if l["seq"] != float64(i+1) {
			t.Fatalf("line %d has seq %v", i, l["seq"])
		}
	}

	ends := eventsOf(lines, "conn_end")
	if len(ends) != 4 {
		t.Fatalf("%d conn_end lines for 4 connections: %v", len(ends), ends)
	}
	byConn := map[string]map[string]any{}
	hexID := regexp.MustCompile(`^[0-9a-f]{12}$`)
	for _, e := range ends {
		id, _ := e["conn"].(string)
		if !hexID.MatchString(id) {
			t.Errorf("conn %q is not 12 hex digits", id)
		}
		if byConn[id] != nil {
			t.Errorf("conn %s twice", id)
		}
		byConn[id] = e
		if !slices.Contains(socks5.Results(), e["result"].(string)) {
			t.Errorf("result %v is outside the closed set", e["result"])
		}
	}
	for i, id := range ids {
		if byConn[id] == nil {
			t.Fatalf("the client's id %q of connection %d is not in the journal", id, i)
		}
	}
	check := func(id string, want map[string]any) {
		t.Helper()
		got := byConn[id]
		for k, v := range want {
			if got[k] != v {
				t.Errorf("conn %s: %s = %v, want %v (%v)", id, k, got[k], v, got)
			}
		}
	}
	echoPort := float64(netip.MustParseAddrPort(echo).Port())
	check(ids[0], map[string]any{"account": "alice", "auth": "key", "transport": "obfs", "cmd": "connect",
		"result": "ok", "dst_net": "127.0.0.0/24", "dst_port": echoPort, "dst_kind": "name", "dial_tries": float64(1)})
	check(ids[1], map[string]any{"account": "bob", "auth": "password", "result": "ok", "dst_kind": "ip"})
	check(ids[2], map[string]any{"account": "unknown", "result": "auth_failed", "stage": "auth"})
	if _, ok := byConn[ids[2]]["auth"]; ok {
		t.Error("a refused login carries an auth method")
	}
	plainLines := 0
	for _, e := range ends {
		if e["transport"] == "plain" {
			plainLines++
			if e["account"] != "bob" || e["result"] != "ok" {
				t.Errorf("plain line: %v", e)
			}
		}
	}
	if plainLines != 1 {
		t.Errorf("%d plain lines, want 1", plainLines)
	}
}

func TestTheJournalIsOffByDefaultAndNeedsAFile(t *testing.T) {
	if DefaultConfig().SessionLog != "" {
		t.Fatal("the journal is on by default")
	}
	base := Config{Port: "0", RequireAuth: false}
	for _, tc := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{SessionLog: SessionLogOff}, true},
		{Config{SessionLog: SessionLogAll}, false},
		{Config{SessionLog: "verbose", SessionLogFile: "x"}, false},
		{Config{SessionLog: SessionLogAbnormal, SessionLogFile: "x", SessionLogDst: "host"}, false},
		{Config{SessionLog: SessionLogAbnormal, SessionLogFile: "x", SessionLogMaxAge: -1}, false},
		{Config{SessionLog: SessionLogAbnormal, SessionLogFile: "x", SessionLogDst: SessionLogDstNone}, true},
	} {
		cfg := base
		cfg.SessionLog, cfg.SessionLogFile = tc.cfg.SessionLog, tc.cfg.SessionLogFile
		cfg.SessionLogDst, cfg.SessionLogMaxAge = tc.cfg.SessionLogDst, tc.cfg.SessionLogMaxAge
		err := ValidateConfig(cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
	}
}

// A journal that cannot be opened stops Start, the way a TRANSPORT_ADVICE_FILE
// that cannot be read does: a server running without the journal it was told
// to keep is a server nobody can answer for.
func TestAJournalThatCannotBeOpenedStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{Port: reservePort(t), ListenIP: "127.0.0.1",
		SessionLog: SessionLogAll, SessionLogFile: filepath.Join(blocker, "sessions.jsonl"),
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "SESSION_LOG_FILE") {
		t.Fatalf("Start: %v", err)
	}
	_ = srv.Stop()
}

func TestAStartThatFailsAfterTheJournalClosesIt(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	_, port, _ := net.SplitHostPort(busy.Addr().String())
	srv, err := NewServer(Config{Port: port, ListenIP: "127.0.0.1",
		SessionLog: SessionLogAll, SessionLogFile: filepath.Join(t.TempDir(), "sessions.jsonl"),
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded on a busy port")
	}
	if srv.journal.Load() != nil {
		t.Fatal("the journal stayed open after a failed Start")
	}
}

func endedSeries(t *testing.T, reader sdkmetric.Reader, name string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, p := range sum.DataPoints {
				var parts []string
				for _, kv := range p.Attributes.ToSlice() {
					parts = append(parts, string(kv.Key)+"="+kv.Value.AsString())
				}
				out[strings.Join(parts, ",")] += p.Value
			}
		}
	}
	return out
}

// The new counters start with every pair of their closed sets at zero, and a
// connection lands in exactly one series.
func TestTheEndOfAConnectionIsCountedWithClosedLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	echo := startEchoServer(t)
	port := reservePort(t)
	srv := startServer(t, Config{Port: port, ListenIP: "127.0.0.1", Telemetry: telemetry})

	ended := endedSeries(t, reader, "s5core_connections_ended_total")
	if want := 3 * len(socks5.Kinds()) * len(socks5.Results()); len(ended) != want {
		t.Fatalf("%d series, want %d", len(ended), want)
	}
	if n := len(endedSeries(t, reader, "s5core_dial_outcomes_total")); n != 2*len(socks5.DialOutcomes()) {
		t.Fatalf("%d dial series", n)
	}
	if n := len(endedSeries(t, reader, "s5core_udp_egress_rotations_total")); n != len(socks5.RotationOutcomes()) {
		t.Fatalf("%d rotation series", n)
	}
	logs := endedSeries(t, reader, "s5core_log_lines_total")
	if len(logs) != len(logging.ServiceLevels())+len(logging.JournalLevels()) {
		t.Fatalf("log series: %v", logs)
	}

	c, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(echo)
	greetAndRequest(t, c, ap.Addr().String(), int(ap.Port()))
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for srv.connsEnded.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	ended = endedSeries(t, reader, "s5core_connections_ended_total")
	var total int64
	for series, n := range ended {
		total += n
		if n == 1 && !strings.HasPrefix(series, "kind=connect,result=") {
			t.Errorf("counted as %s", series)
		}
	}
	if total != 1 {
		t.Fatalf("%d connections counted, want 1: %v", total, ended)
	}
	if got := endedSeries(t, reader, "s5core_dial_outcomes_total")["family=v4,outcome=ok"]; got != 1 {
		t.Errorf("dial v4/ok = %d", got)
	}
}

func TestAbnormalKeepsWhatAComplaintNeeds(t *testing.T) {
	ok := func(change func(*socks5.ConnEnd)) *socks5.ConnEnd {
		e := &socks5.ConnEnd{Command: socks5.CmdConnect, Result: socks5.ResultOK, ClosedBy: socks5.ClosedByClient, DialTries: 1, Down: 10}
		if change != nil {
			change(e)
		}
		return e
	}
	cases := map[string]struct {
		e    *socks5.ConnEnd
		want bool
	}{
		"ok":           {ok(nil), false},
		"failed":       {ok(func(e *socks5.ConnEnd) { e.Result = socks5.ResultDialTimeout }), true},
		"reset":        {ok(func(e *socks5.ConnEnd) { e.ClosedBy = socks5.ClosedByReset }), true},
		"timeout":      {ok(func(e *socks5.ConnEnd) { e.ClosedBy = socks5.ClosedByServerTimeout }), true},
		"backup":       {ok(func(e *socks5.ConnEnd) { e.DialBackups = 1 }), true},
		"nothing back": {ok(func(e *socks5.ConnEnd) { e.Down = 0 }), true},
	}
	for name, tc := range cases {
		if got := abnormal(tc.e); got != tc.want {
			t.Errorf("%s: abnormal = %v", name, got)
		}
	}
}

// failingFile refuses every write until told otherwise.
type failingFile struct {
	mu   sync.Mutex
	fail bool
	buf  bytes.Buffer
}

func (f *failingFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, errors.New("no space left on device")
	}
	return f.buf.Write(p)
}

func (f *failingFile) Close() error { return nil }

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// The minute summary is written once a minute and only for a minute in which
// something ended; the journal gets a line per account.
func TestTheMinuteSummaryIsWrittenOnlyForABusyMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		out := &lockedBuffer{}
		logger := slog.New(slog.NewJSONHandler(out, nil))
		file := &failingFile{}
		j := &sessionJournal{Journal: logging.NewJournal(file, "b00710ad"), all: true, dst: true}
		m := newMinuteSummary()
		ctx, cancel := context.WithCancel(context.Background())
		go m.run(ctx, logger, func() *sessionJournal { return j }, "b00710ad")

		time.Sleep(MinuteInterval)
		synctest.Wait()
		if out.Len() != 0 {
			t.Fatalf("an idle minute wrote %q", out.String())
		}

		m.record(&socks5.ConnEnd{Command: socks5.CmdConnect, Result: socks5.ResultOK, Account: "alice", Up: 3, Down: 5}, true)
		m.record(&socks5.ConnEnd{Command: socks5.CmdConnect, Result: socks5.ResultDialTimeout, Account: "alice"}, true)
		m.record(&socks5.ConnEnd{Command: socks5.AssociationTunnel, Result: socks5.ResultOK, Account: "bob", Rotations: 4}, true)
		time.Sleep(MinuteInterval - time.Nanosecond)
		synctest.Wait()
		if out.Len() != 0 {
			t.Fatal("the summary came before the minute was out")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		var line map[string]any
		if err := json.Unmarshal([]byte(out.String()), &line); err != nil {
			t.Fatalf("%q: %v", out.String(), err)
		}
		results, _ := line["results"].(map[string]any)
		if line["event"] != "minute" || line["conns"] != float64(3) || results["ok"] != float64(2) ||
			results["dial_timeout"] != float64(1) || line["udp_rotations_gave_up"] != float64(1) {
			t.Errorf("summary: %v", line)
		}
		if strings.Contains(out.String(), "alice") {
			t.Error("the service log names an account")
		}

		j.Flush()
		file.mu.Lock()
		accounts := strings.Split(strings.TrimSpace(file.buf.String()), "\n")
		file.mu.Unlock()
		if len(accounts) != 2 || !strings.Contains(accounts[0], `"account":"alice","conns":2,"failed":1`) ||
			!strings.Contains(accounts[1], `"account":"bob","conns":1,"failed":0,"assocs":1`) {
			t.Errorf("account lines: %q", accounts)
		}

		out.Reset()
		time.Sleep(MinuteInterval)
		synctest.Wait()
		if out.Len() != 0 {
			t.Errorf("the next idle minute wrote %q", out.String())
		}
		cancel()
		_ = j.Close()
	})
}

func benchEnd() *socks5.ConnEnd {
	return &socks5.ConnEnd{Spoke: true, Command: socks5.CmdConnect, Account: "alice", Auth: socks5.AuthKey,
		Result: socks5.ResultOK, ClosedBy: socks5.ClosedByClient, Dst: netip.MustParseAddrPort("172.217.132.72:443"),
		DialTime: 163 * time.Millisecond, DialTries: 1, FirstByte: 41 * time.Millisecond,
		Duration: 95 * time.Second, Up: 12345, Down: 9876543,
		DialOutcomes: []socks5.DialOutcome{{Outcome: socks5.DialOK}}}
}

type discardFile struct{}

func (discardFile) Write(p []byte) (int, error) { return len(p), nil }
func (discardFile) Close() error                { return nil }

func benchServer(b testing.TB, journal bool) *Server {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		b.Fatal(err)
	}
	srv, err := NewServer(Config{Port: "0", Telemetry: telemetry, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		b.Fatal(err)
	}
	if journal {
		j := &sessionJournal{Journal: logging.NewJournal(discardFile{}, "b00710ad"), all: true, dst: true}
		srv.journal.Store(j)
		b.Cleanup(func() { _ = j.Close() })
	}
	return srv
}

// The cost of the end of one connection: metrics and the minute summary
// always, plus a journal line when the journal is on.
func BenchmarkConnEnd(b *testing.B) {
	for _, on := range []bool{false, true} {
		name := "journal_off"
		if on {
			name = "journal_on"
		}
		b.Run(name, func(b *testing.B) {
			srv := benchServer(b, on)
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			e := benchEnd()
			b.ReportAllocs()
			for b.Loop() {
				srv.connEnded(conn, e)
			}
		})
	}
}

// A journal line is built into the journal's buffer: the plain listener's
// random id is its one allocation, and with the journal off the end of a
// connection allocates nothing.
func TestTheEndOfAConnectionCostsFewAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	for _, tc := range []struct {
		journal bool
		max     float64
	}{{false, 0}, {true, 1}} {
		srv := benchServer(t, tc.journal)
		conn, peer := net.Pipe()
		e := benchEnd()
		got := testing.AllocsPerRun(200, func() { srv.connEnded(conn, e) })
		_ = conn.Close()
		_ = peer.Close()
		if got > tc.max {
			t.Errorf("journal %v: %.1f allocations per connection end, want at most %.0f", tc.journal, got, tc.max)
		}
	}
}
