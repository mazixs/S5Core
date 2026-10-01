// Package logging centralizes log level handling.
//
// The level lives in a single *slog.LevelVar that is handed to the handler
// once, at startup, and mutated afterwards. That is what makes the level
// changeable on a running process: slog reads the LevelVar on every record,
// and LevelVar is safe for concurrent use.
//
// Debug output on this server is protocol diagnostics - the difference between
// "the connection failed" and "the connection failed while reading the version
// byte". It must be reachable without a rebuild and without a restart, because
// the failures worth diagnosing happen on machines that are already in the
// field. See docs/design/observability-policy.md for what may and may not be logged.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

const (
	// EnvVar is the environment variable read at startup and on reload.
	EnvVar = "LOG_LEVEL"
	// FileEnvVar names a file holding a single level word. The environment of a
	// running process cannot be changed from outside, so on a live server this
	// file - not EnvVar - is what actually makes SIGHUP able to change the
	// level. When it is set and readable, it wins over EnvVar.
	FileEnvVar = "LOG_LEVEL_FILE"
)

// levelVar backs every logger built by this package. A single variable is
// intentional: one SIGHUP changes the level everywhere at once.
var levelVar = new(slog.LevelVar)

// ParseLevel maps a configuration string to a slog level. Accepted spellings
// are debug, info, warn (warning) and error, in any case. An empty string means
// info, so an unset LOG_LEVEL keeps the previous default behaviour.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
	}
}

// Level reports the current level.
func Level() slog.Level { return levelVar.Level() }

// SetLevelFromEnv re-reads the configured level and applies it. LOG_LEVEL_FILE
// takes precedence when it is set and readable; otherwise LOG_LEVEL is used.
// It returns the level now in effect and an error if the value was not
// understood - in that case the previous level is kept, because dropping to a
// default during a reload would silently turn diagnostics off mid-incident.
func SetLevelFromEnv() (slog.Level, error) {
	raw := os.Getenv(EnvVar)
	if path := os.Getenv(FileEnvVar); path != "" {
		b, err := readLevelFile(path)
		if err != nil {
			return levelVar.Level(), fmt.Errorf("read %s=%s: %w", FileEnvVar, path, err)
		}
		raw = string(b)
	}
	l, err := ParseLevel(raw)
	if err != nil {
		return levelVar.Level(), err
	}
	levelVar.Set(l)
	return l, nil
}

// maxLevelFileBytes bounds the read of LOG_LEVEL_FILE for the reason
// cmd/s5core/advice_file.go gives: the reload runs on the signal goroutine,
// and a path that never ends (/dev/zero, a file still being written) would
// stop every later SIGHUP from being handled.
const maxLevelFileBytes = 4 << 10

func readLevelFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxLevelFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxLevelFileBytes {
		return nil, fmt.Errorf("larger than %d bytes, which no level is", maxLevelFileBytes)
	}
	return b, nil
}

// ToggleDebug switches between debug and info and reports the new level.
// This is the zero-configuration path: an operator who did not set up
// LOG_LEVEL_FILE in advance can still turn diagnostics on during an incident,
// with a signal and nothing else.
func ToggleDebug() slog.Level {
	if levelVar.Level() == slog.LevelDebug {
		levelVar.Set(slog.LevelInfo)
	} else {
		levelVar.Set(slog.LevelDebug)
	}
	return levelVar.Level()
}

// New builds a JSON logger bound to the shared level variable.
func New(w io.Writer) *slog.Logger {
	return slog.New(counting{slog.NewJSONHandler(w, &slog.HandlerOptions{Level: levelVar})})
}

// NewTee is New for a file, plus a short text copy of the lines at or above
// consoleLevel for a console. The file keeps the shared level; the console
// line is only built when its own level lets it through.
func NewTee(file, console io.Writer, consoleLevel slog.Leveler) *slog.Logger {
	return slog.New(counting{tee{
		slog.NewJSONHandler(file, &slog.HandlerOptions{Level: levelVar}),
		slog.NewTextHandler(console, &slog.HandlerOptions{Level: consoleLevel}),
	}})
}

// The service log's own line counts by level, and the lines its writer
// refused, for s5core_log_lines_total and s5core_log_dropped_total.
var (
	serviceLines   [4]atomic.Uint64
	serviceDropped atomic.Uint64
)

// ServiceLevels names the levels ServiceLines reports, in its order.
func ServiceLevels() []string { return []string{"debug", "info", "warn", "error"} }

// ServiceLines is how many lines the service log wrote, by level, in the order
// of ServiceLevels.
func ServiceLines(level int) uint64 { return serviceLines[level].Load() }

// ServiceDropped is how many lines the service log could not write.
func ServiceDropped() uint64 { return serviceDropped.Load() }

func levelIndex(l slog.Level) int {
	switch {
	case l < slog.LevelInfo:
		return 0
	case l < slog.LevelWarn:
		return 1
	case l < slog.LevelError:
		return 2
	}
	return 3
}

type counting struct{ slog.Handler }

// Handle writes the time in UTC, as the session journal does: lines of a
// client on a laptop and of a server in a container must line up as written.
func (h counting) Handle(ctx context.Context, r slog.Record) error {
	r.Time = r.Time.UTC()
	err := h.Handler.Handle(ctx, r)
	if err != nil {
		serviceDropped.Add(1)
	} else {
		serviceLines[levelIndex(r.Level)].Add(1)
	}
	return err
}

func (h counting) WithAttrs(as []slog.Attr) slog.Handler { return counting{h.Handler.WithAttrs(as)} }
func (h counting) WithGroup(n string) slog.Handler       { return counting{h.Handler.WithGroup(n)} }

type tee [2]slog.Handler

func (t tee) Enabled(ctx context.Context, l slog.Level) bool {
	return t[0].Enabled(ctx, l) || t[1].Enabled(ctx, l)
}

func (t tee) Handle(ctx context.Context, r slog.Record) error {
	var err error
	for _, h := range t {
		if h.Enabled(ctx, r.Level) {
			if e := h.Handle(ctx, r); e != nil && err == nil {
				err = e
			}
		}
	}
	return err
}

func (t tee) WithAttrs(as []slog.Attr) slog.Handler {
	return tee{t[0].WithAttrs(as), t[1].WithAttrs(as)}
}

func (t tee) WithGroup(n string) slog.Handler {
	return tee{t[0].WithGroup(n), t[1].WithGroup(n)}
}

// Setup builds the process logger from LOG_LEVEL, installs it as the slog
// default and returns it together with any parse error. The error is returned
// rather than fatal: a typo in LOG_LEVEL should not prevent the proxy from
// starting, it should be reported and fall back to info.
func Setup(w io.Writer) (*slog.Logger, error) {
	_, err := SetLevelFromEnv()
	logger := New(w)
	slog.SetDefault(logger)
	return logger, err
}
