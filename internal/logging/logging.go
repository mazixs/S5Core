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
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
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

// SetLevel replaces the current level. It is safe to call at any time,
// including from a signal handler while connections are being served.
func SetLevel(l slog.Level) { levelVar.Set(l) }

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
		b, err := os.ReadFile(path)
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
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: levelVar}))
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
