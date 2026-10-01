package s5server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/buildinfo"
	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// What the session journal records (Config.SessionLog). The journal is the
// one place an account and a destination network may be written; see
// "Журнал сессий" in docs/design/observability-policy.md.
const (
	SessionLogOff      = "off"
	SessionLogAbnormal = "abnormal"
	SessionLogAll      = "all"
)

// How much of a destination the journal keeps (Config.SessionLogDst).
const (
	SessionLogDstNet  = "net"
	SessionLogDstNone = "none"
)

// Defaults of the journal's own rotation.
const (
	DefaultSessionLogMaxSize  = 20 << 20
	DefaultSessionLogMaxFiles = 10
	DefaultSessionLogMaxAge   = 7 * 24 * time.Hour
)

// MinuteInterval is how often the summaries are written.
const MinuteInterval = time.Minute

func sessionLogOn(cfg Config) bool {
	return cfg.SessionLog == SessionLogAbnormal || cfg.SessionLog == SessionLogAll
}

func validateSessionLog(cfg Config) error {
	switch cfg.SessionLog {
	case "", SessionLogOff:
		return nil
	case SessionLogAbnormal, SessionLogAll:
	default:
		return fmt.Errorf("SESSION_LOG must be off, abnormal or all, got %q", cfg.SessionLog)
	}
	if cfg.SessionLogFile == "" {
		return fmt.Errorf("SESSION_LOG=%s requires SESSION_LOG_FILE", cfg.SessionLog)
	}
	switch cfg.SessionLogDst {
	case "", SessionLogDstNet, SessionLogDstNone:
	default:
		return fmt.Errorf("SESSION_LOG_DST must be net or none, got %q", cfg.SessionLogDst)
	}
	if cfg.SessionLogMaxSize < 0 || cfg.SessionLogMaxFiles < 0 || cfg.SessionLogMaxAge < 0 {
		return fmt.Errorf("SESSION_LOG_MAX_SIZE_MB, SESSION_LOG_MAX_FILES and SESSION_LOG_MAX_AGE must not be negative")
	}
	return nil
}

func observeLogLines(_ context.Context, o metric.Int64Observer) error {
	for i, level := range logging.ServiceLevels() {
		o.Observe(int64(logging.ServiceLines(i)), metric.WithAttributes(
			attribute.String("stream", "service"), attribute.String("level", level)))
	}
	for i, level := range logging.JournalLevels() {
		o.Observe(int64(logging.JournalLines(i)), metric.WithAttributes(
			attribute.String("stream", "sessions"), attribute.String("level", level)))
	}
	return nil
}

func observeLogDropped(_ context.Context, o metric.Int64Observer) error {
	o.Observe(int64(logging.ServiceDropped()), metric.WithAttributes(attribute.String("stream", "service")))
	o.Observe(int64(logging.JournalDropped()), metric.WithAttributes(attribute.String("stream", "sessions")))
	return nil
}

// connEndMetrics holds the attribute sets of the three end-of-connection
// counters, built once and every pair set to zero, so a connection's end is a
// map lookup and an Add.
type connEndMetrics struct {
	t         *Telemetry
	ended     map[[3]string][]metric.AddOption
	dial      map[[2]string][]metric.AddOption
	rotations map[string][]metric.AddOption
}

func newConnEndMetrics(t *Telemetry) *connEndMetrics {
	if t == nil || t.ConnectionsEnded == nil || t.DialOutcomes == nil || t.UDPEgressRotations == nil {
		return nil
	}
	m := &connEndMetrics{
		t:         t,
		ended:     map[[3]string][]metric.AddOption{},
		dial:      map[[2]string][]metric.AddOption{},
		rotations: map[string][]metric.AddOption{},
	}
	ctx := context.Background()
	for _, transport := range []string{TransportPlain, TransportObfs, TransportWS} {
		for _, kind := range socks5.Kinds() {
			for _, result := range socks5.Results() {
				o := metric.WithAttributes(attribute.String("transport", transport),
					attribute.String("kind", kind), attribute.String("result", result))
				m.ended[[3]string{transport, kind, result}] = []metric.AddOption{o}
				t.ConnectionsEnded.Add(ctx, 0, o)
			}
		}
	}
	for _, family := range []string{"v4", "v6"} {
		for _, outcome := range socks5.DialOutcomes() {
			o := metric.WithAttributes(attribute.String("family", family), attribute.String("outcome", outcome))
			m.dial[[2]string{family, outcome}] = []metric.AddOption{o}
			t.DialOutcomes.Add(ctx, 0, o)
		}
	}
	for _, outcome := range socks5.RotationOutcomes() {
		o := metric.WithAttributes(attribute.String("outcome", outcome))
		m.rotations[outcome] = []metric.AddOption{o}
		t.UDPEgressRotations.Add(ctx, 0, o)
	}
	return m
}

func (m *connEndMetrics) record(transport string, e *socks5.ConnEnd) {
	if m == nil {
		return
	}
	ctx := context.Background()
	if o, ok := m.ended[[3]string{transport, e.Kind(), e.Result}]; ok {
		m.t.ConnectionsEnded.Add(ctx, 1, o...)
	}
	for _, d := range e.DialOutcomes {
		family := "v4"
		if d.V6 {
			family = "v6"
		}
		if o, ok := m.dial[[2]string{family, d.Outcome}]; ok {
			m.t.DialOutcomes.Add(ctx, 1, o...)
		}
	}
	if o, ok := m.rotations[e.RotationOutcome()]; ok {
		m.t.UDPEgressRotations.Add(ctx, 1, o...)
	}
}

var resultIndex = func() map[string]int {
	m := map[string]int{}
	for i, r := range socks5.Results() {
		m[r] = i
	}
	return m
}()

// minuteSummary is what the server says once a minute: outcomes without
// names in the service log, and per account in the journal.
type minuteSummary struct {
	results   []atomic.Int64
	assocs    atomic.Int64
	rotations atomic.Int64
	gaveUp    atomic.Int64
	backups   atomic.Int64

	// accounts is kept only while a journal is open.
	mu       sync.Mutex
	accounts map[string]*accountMinute
}

type accountMinute struct {
	conns, failed, assocs, backups, up, down int64
}

func newMinuteSummary() *minuteSummary {
	return &minuteSummary{
		results:  make([]atomic.Int64, len(socks5.Results())),
		accounts: map[string]*accountMinute{},
	}
}

func (m *minuteSummary) record(e *socks5.ConnEnd, perAccount bool) {
	if i, ok := resultIndex[e.Result]; ok {
		m.results[i].Add(1)
	}
	udp := e.Kind() == socks5.KindUDP
	if udp {
		m.assocs.Add(1)
	}
	if e.Rotations > 0 {
		m.rotations.Add(e.Rotations)
		if e.RotationOutcome() == socks5.RotationGaveUp {
			m.gaveUp.Add(1)
		}
	}
	m.backups.Add(int64(e.DialBackups))
	if !perAccount {
		return
	}
	m.mu.Lock()
	a := m.accounts[accountName(e)]
	if a == nil {
		a = &accountMinute{}
		m.accounts[accountName(e)] = a
	}
	a.conns++
	if e.Result != socks5.ResultOK {
		a.failed++
	}
	if udp {
		a.assocs++
	}
	a.backups += int64(e.DialBackups)
	a.up += e.Up
	a.down += e.Down
	m.mu.Unlock()
}

// emit writes the minute that has passed and starts the next. A minute in
// which nothing ended writes nothing.
func (m *minuteSummary) emit(logger *slog.Logger, j *sessionJournal, boot string) {
	var conns int64
	results := make([]slog.Attr, 0, len(m.results))
	for i, name := range socks5.Results() {
		if n := m.results[i].Swap(0); n > 0 {
			conns += n
			results = append(results, slog.Int64(name, n))
		}
	}
	assocs, rotations, gaveUp, backups := m.assocs.Swap(0), m.rotations.Swap(0), m.gaveUp.Swap(0), m.backups.Swap(0)
	if conns > 0 {
		logger.LogAttrs(context.Background(), slog.LevelInfo, "Minute summary",
			slog.String("event", "minute"),
			slog.String("boot", boot),
			slog.Int64("conns", conns),
			slog.Attr{Key: "results", Value: slog.GroupValue(results...)},
			slog.Int64("assocs", assocs),
			slog.Int64("dial_backups", backups),
			slog.Int64("udp_rotations", rotations),
			slog.Int64("udp_rotations_gave_up", gaveUp),
		)
	}

	m.mu.Lock()
	accounts := m.accounts
	m.accounts = map[string]*accountMinute{}
	m.mu.Unlock()
	if j == nil || len(accounts) == 0 {
		return
	}
	names := make([]string, 0, len(accounts))
	for name := range accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		a := accounts[name]
		j.Write("INFO", "account_minute", func(l *logging.Line) {
			l.Str("account", name)
			l.Int("conns", a.conns)
			l.Int("failed", a.failed)
			l.Int("assocs", a.assocs)
			l.Int("dial_backups", a.backups)
			l.Int("up", a.up)
			l.Int("down", a.down)
		})
	}
}

func (m *minuteSummary) run(ctx context.Context, logger *slog.Logger, journal func() *sessionJournal, boot string) {
	t := time.NewTicker(MinuteInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.emit(logger, journal(), boot)
		}
	}
}

// sessionJournal is the journal file of one server.
type sessionJournal struct {
	*logging.Journal
	file *logging.RotatingFile
	all  bool
	dst  bool
	// prev is the last event of the file the previous process left.
	prev string
}

func openSessionJournal(cfg Config, boot string) (*sessionJournal, error) {
	opts := logging.FileOptions{
		Path:     cfg.SessionLogFile,
		MaxSize:  cfg.SessionLogMaxSize,
		Keep:     cfg.SessionLogMaxFiles,
		MaxAge:   cfg.SessionLogMaxAge,
		Compress: true,
	}
	if opts.MaxSize == 0 {
		opts.MaxSize = DefaultSessionLogMaxSize
	}
	if opts.Keep == 0 {
		opts.Keep = DefaultSessionLogMaxFiles
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = DefaultSessionLogMaxAge
	}
	prev := logging.LastEvent(cfg.SessionLogFile)
	file, err := logging.OpenRotating(opts)
	if err != nil {
		return nil, fmt.Errorf("SESSION_LOG_FILE is not usable: %w", err)
	}
	return &sessionJournal{
		Journal: logging.NewJournal(file, boot),
		file:    file,
		all:     cfg.SessionLog == SessionLogAll,
		dst:     cfg.SessionLogDst != SessionLogDstNone,
		prev:    prev,
	}, nil
}

// abnormal is what SESSION_LOG=abnormal keeps of the connections: failures,
// resets and timeouts, dials that needed a backup socket, and a dial that
// succeeded and then got nothing back - the shape of a hole on the path.
func abnormal(e *socks5.ConnEnd) bool {
	switch {
	case e.Result != socks5.ResultOK:
		return true
	case e.ClosedBy == socks5.ClosedByReset, e.ClosedBy == socks5.ClosedByServerTimeout:
		return true
	case e.DialBackups > 0:
		return true
	case e.Command == socks5.CmdConnect && e.DialTries > 0 && e.Down == 0:
		return true
	}
	return false
}

func accountName(e *socks5.ConnEnd) string {
	if e.Account == "" {
		return "-"
	}
	return e.Account
}

// dstNet is the /24 of an IPv4 destination and the /48 of an IPv6 one.
func dstNet(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// connEnd writes the line of one connection, or of one association.
func (j *sessionJournal) connEnd(id, transport, client string, e *socks5.ConnEnd) {
	udp := e.Kind() == socks5.KindUDP
	event := "conn_end"
	if udp {
		event = "assoc_end"
	} else if !j.all && !abnormal(e) {
		return
	}
	j.Write("INFO", event, func(l *logging.Line) {
		l.Str("conn", id)
		l.Str("account", accountName(e))
		if e.Auth != "" {
			l.Str("auth", e.Auth)
		}
		l.Str("transport", transport)
		if client != "" {
			l.Str("client", client)
		}
		if e.Command != "" {
			l.Str("cmd", e.Command)
		}
		if j.dst && e.Dst.IsValid() {
			l.Prefix("dst_net", dstNet(e.Dst.Addr()))
			l.Int("dst_port", int64(e.Dst.Port()))
			if e.DstName {
				l.Str("dst_kind", "name")
			} else {
				l.Str("dst_kind", "ip")
			}
		}
		l.Str("result", e.Result)
		if e.Stage != "" {
			l.Str("stage", e.Stage)
		}
		if e.ClosedBy != "" {
			if udp {
				l.Str("reason", e.ClosedBy)
			} else {
				l.Str("closed_by", e.ClosedBy)
			}
		}
		if e.DialTries > 0 {
			l.Ms("dial_ms", e.DialTime)
			l.Int("dial_tries", int64(e.DialTries))
			l.Int("dial_backups", int64(e.DialBackups))
			if e.DialBackupWon {
				l.Bool("dial_backup_won", true)
			}
		}
		if e.FirstByte > 0 {
			l.Ms("first_byte_ms", e.FirstByte)
		}
		l.Ms("dur_ms", e.Duration)
		l.Int("up", e.Up)
		l.Int("down", e.Down)
		if udp {
			l.Int("dgram_up", e.DatagramsUp)
			l.Int("dgram_down", e.DatagramsDown)
			if e.Rotations > 0 {
				l.Int("rotations", e.Rotations)
				l.Bool("answered", e.Answered)
			}
		}
	})
}

func (j *sessionJournal) close() {
	_ = j.Close()
}

// randomLogID names a connection that has no session secret to derive one
// from: the plain listener.
func randomLogID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// connEnded is socks5.Config.OnConnEnd. A peer that never sent a SOCKS5
// byte is a probe, not a session, and is seen only in the obfuscation
// metrics.
func (s *Server) connEnded(conn net.Conn, e *socks5.ConnEnd) {
	if !e.Spoke {
		return
	}
	s.connsEnded.Add(1)
	transport := session.Of(conn).Transport()
	s.endMetrics.record(transport, e)
	j := s.journal.Load()
	s.minutes.record(e, j != nil)
	if j == nil {
		return
	}
	id := obfs.LogIDOf(conn)
	if id == "" {
		id = randomLogID()
	}
	var client string
	if build := obfs.ClientBuildOf(conn); build != "" {
		client = sanitizeVersion(build)
	}
	j.connEnd(id, transport, client, e)
}

// openJournal opens the session journal, if one is configured, and writes
// the start of this process into it.
func (s *Server) openJournal() error {
	if !sessionLogOn(s.cfg) {
		return nil
	}
	j, err := openSessionJournal(s.cfg, s.boot)
	if err != nil {
		return err
	}
	s.journal.Store(j)
	unclean := j.prev != "" && j.prev != "process_stop"
	j.Write("INFO", "process_start", func(l *logging.Line) {
		l.Str("boot", s.boot)
		l.Str("version", buildinfo.Version())
		l.Str("go_version", buildinfo.GoVersion())
		l.Int("pid", int64(os.Getpid()))
		l.Str("transports", transportSummary(s.cfg))
		l.Str("session_log", s.cfg.SessionLog)
		l.Bool("prev_unclean", unclean)
	})
	if unclean {
		s.logger.Warn("The previous process did not stop cleanly: its session journal has no process_stop",
			"event", "process_start", "boot", s.boot, "last_event", j.prev)
	}
	return nil
}

// closeJournal writes the stop of this process and closes the journal. It
// runs after every connection handler has returned, so every conn_end is in.
func (s *Server) closeJournal() {
	j := s.journal.Swap(nil)
	uptime := time.Since(s.started)
	open := s.openSessions()
	if j != nil {
		j.Write("INFO", "process_stop", func(l *logging.Line) {
			l.Str("boot", s.boot)
			l.Int("uptime_s", int64(uptime/time.Second))
			l.Int("conns", s.connsEnded.Load())
			l.Int("open", open)
		})
		j.close()
	}
	s.logger.Info("Server stopped",
		"event", "process_stop",
		"boot", s.boot,
		"uptime_s", int64(uptime/time.Second),
		"conns", s.connsEnded.Load(),
		"open", open,
	)
}

func (s *Server) openSessions() int64 {
	var n int64
	for _, c := range s.sessions.Snapshot() {
		if c.Region == session.RegionProtocol && c.StateName() != "closed" {
			n += c.N
		}
	}
	return n
}

// Boot is the epoch of this server: 8 hex digits drawn at NewServer, written
// into its process markers in both the service log and the session journal.
func (s *Server) Boot() string { return s.boot }

// RecordReload marks a configuration reload (SIGHUP): the session journal is
// reopened, for a rotation done from outside, and both logs get a
// config_reload line naming what failed to reload, if anything.
func (s *Server) RecordReload(failed ...string) {
	n := s.reloads.Add(1)
	j := s.journal.Load()
	if j != nil {
		j.Flush()
		if err := j.file.Reopen(); err != nil {
			s.logger.Error("Failed to reopen the session journal", "error", err)
		}
		j.Write("INFO", "config_reload", func(l *logging.Line) {
			l.Str("boot", s.boot)
			l.Int("reload", n)
			if len(failed) > 0 {
				l.Str("failed", strings.Join(failed, ","))
			}
		})
	}
	s.logger.Info("Configuration reloaded",
		"event", "config_reload",
		"boot", s.boot,
		"reload", n,
		"failed", failed,
	)
}

func sessionLogMode(cfg Config) string {
	if sessionLogOn(cfg) {
		return cfg.SessionLog
	}
	return SessionLogOff
}
