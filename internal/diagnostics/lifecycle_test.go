package diagnostics

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
)

func TestStartLatencyIsOffWithoutItsDirectory(t *testing.T) {
	t.Setenv(envDir, "")
	stop := StartLatency()
	if current.Load() != nil {
		t.Fatal("a recorder without a directory")
	}
	stop()
}

// The recorder starts in the background, creates its directory private and
// runs until stopped; stopping saves the incident being written.
func TestTheRecorderRunsUntilStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "new", "diag")
		t.Setenv(envDir, dir)
		t.Setenv(envRunID, "both-ends")
		stop := StartLatency()
		synctest.Wait()
		r := current.Load()
		if r == nil {
			t.Fatal("no recorder")
		}
		privatefstest.RequirePrivate(t, dir)
		id := uuid.New().String()
		writeMarker(t, dir, id)
		time.Sleep(5 * time.Second)
		stop()
		if current.Load() != nil || !r.stopped.Load() {
			t.Fatal("the recorder still runs")
		}
		m, events := readIncident(t, dir, id)
		if !m.Window.ShutdownBeforePostEnd || m.RunID != "both-ends" || len(events) == 0 {
			t.Fatalf("manifest %+v, %d events", m.Window, len(events))
		}
	})
}

// A recorder that becomes ready after the process asked it to stop stops
// itself and leaves nothing running.
func TestARecorderReadyAfterTheStopStopsItself(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Setenv(envDir, filepath.Join(t.TempDir(), "diag"))
		StartLatency()()
		synctest.Wait()
		if current.Load() != nil {
			t.Fatal("a recorder runs after the stop")
		}
	})
}

// Of two starts, the second leaves the first alone.
func TestASecondStartLeavesTheFirstAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Setenv(envDir, filepath.Join(t.TempDir(), "diag"))
		stop := StartLatency()
		synctest.Wait()
		first := current.Load()
		StartLatency()()
		synctest.Wait()
		if current.Load() != first || first.stopped.Load() {
			t.Fatal("the second start took the first one's place")
		}
		stop()
	})
}

// A directory others may reach, a run ID past its bound and a directory
// that cannot be made stop the recorder before it starts.
func TestTheRecorderNeedsAPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(open, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, start := range map[string]func() error{
		"open": func() error { _, err := newDirRecorder(open, "", false); return err },
		"file": func() error { _, err := newDirRecorder(filepath.Join(file, "diag"), "", false); return err },
		"run ID": func() error {
			_, err := newDirRecorder(filepath.Join(base, "ok"), strings.Repeat("x", runIDMaxBytes+1), false)
			return err
		},
	} {
		if err := start(); err == nil {
			t.Errorf("%s: the recorder started", name)
		}
	}
	t.Setenv(envDir, open)
	synctest.Test(t, func(t *testing.T) {
		stop := StartLatency()
		synctest.Wait()
		if current.Load() != nil {
			t.Fatal("the recorder started in a directory others may reach")
		}
		stop()
	})
}
