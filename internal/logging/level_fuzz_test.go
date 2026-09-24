package logging

import (
	"log/slog"
	"strings"
	"testing"
)

// FuzzParseLevel reads arbitrary LOG_LEVEL and LOG_LEVEL_FILE contents: the
// four level words and "warning" are accepted in any case and with any
// surrounding space, blank is info, and anything else is an error that leaves
// info as the answer. Every level slog prints parses back to itself.
func FuzzParseLevel(f *testing.F) {
	for _, s := range []string{"debug", "INFO", " Warn\n", "warning", "error", "", "trace", "info info", "İNFO"} {
		f.Add(s)
	}

	words := map[string]slog.Level{
		"": slog.LevelInfo, "info": slog.LevelInfo, "debug": slog.LevelDebug,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError,
	}
	f.Fuzz(func(t *testing.T, s string) {
		l, err := ParseLevel(s)
		want, known := words[strings.ToLower(strings.TrimSpace(s))]
		if known != (err == nil) {
			t.Fatalf("ParseLevel(%q) err=%v", s, err)
		}
		if !known {
			want = slog.LevelInfo
		}
		if l != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", s, l, want)
		}
		if back, err := ParseLevel(l.String()); err != nil || back != l {
			t.Fatalf("level %v printed as %q parses as %v, %v", l, l.String(), back, err)
		}
	})
}
