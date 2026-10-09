package s5server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A handshake budget not above the oldest spare a client keeps closes spares
// before they are taken, and the operator hears of it.
func TestAShortHandshakeBudgetIsWarnedAbout(t *testing.T) {
	for _, tc := range []struct {
		budget time.Duration
		warned bool
	}{
		{5 * time.Second, true},
		{10 * time.Second, true},
		{10*time.Second + time.Millisecond, false},
		{DefaultHandshakeTimeout, false},
	} {
		var logs bytes.Buffer
		warnShortHandshake(slog.New(slog.NewTextHandler(&logs, nil)), tc.budget)
		if got := strings.Contains(logs.String(), "level=WARN"); got != tc.warned {
			t.Fatalf("HANDSHAKE_TIMEOUT=%v: warned %v, want %v:\n%s", tc.budget, got, tc.warned, logs.String())
		}
	}
}
