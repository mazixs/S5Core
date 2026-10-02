package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/logging"
)

// openLogFile moves the default logger to LOG_FILE: JSON at LOG_LEVEL in the
// file, short text at LOG_CONSOLE_LEVEL on the console. The last run's file
// goes to archive/ next to it, which keeps LOG_KEEP runs; the rotation is the
// client's own, because on Windows a file the process holds open cannot be
// renamed from outside. Without LOG_FILE the output is what it always was.
func openLogFile(cfg clientParams, console io.Writer) (file *logging.RotatingFile, prevUnclean bool, err error) {
	if cfg.LogFile == "" {
		return nil, false, nil
	}
	consoleLevel, err := logging.ParseLevel(cfg.LogConsoleLevel)
	if err != nil {
		return nil, false, fmt.Errorf("LOG_CONSOLE_LEVEL: %w", err)
	}
	if cfg.LogKeep < 0 || cfg.LogMaxSizeMB < 0 {
		return nil, false, errors.New("LOG_KEEP and LOG_MAX_SIZE_MB must not be negative")
	}
	if info, statErr := os.Stat(cfg.LogFile); statErr == nil && info.Size() > 0 {
		prevUnclean = logging.LastEvent(cfg.LogFile) != eventStop
	}
	file, err = logging.OpenRotating(logging.FileOptions{
		Path:         cfg.LogFile,
		MaxSize:      int64(cfg.LogMaxSizeMB) << 20,
		Keep:         cfg.LogKeep,
		ArchiveDir:   filepath.Join(filepath.Dir(cfg.LogFile), "archive"),
		RotateOnOpen: true,
	})
	if err != nil {
		return nil, false, explainLogFileError(runtime.GOOS, err)
	}
	slog.SetDefault(logging.NewTee(file, console, consoleLevel))
	return file, prevUnclean, nil
}

// explainLogFileError names the usual cause of a failed start on Windows: the
// last run's file goes to archive/ by a rename, and Windows does not rename a
// file another process holds open, which is what a second copy of the client
// with the same LOG_FILE does.
func explainLogFileError(goos string, err error) error {
	var link *os.LinkError
	if goos == "windows" && errors.As(err, &link) && link.Op == "rename" {
		return fmt.Errorf("%w: the file is open in another running copy of the client, "+
			"and Windows cannot rename an open file; stop that copy or give this one its own LOG_FILE", err)
	}
	return err
}

const (
	eventStart  = "process_start"
	eventStop   = "process_stop"
	eventMinute = "minute"
)

// Who ended a relayed TCP connection, as the client sees it.
const (
	closedByApp         = "app"
	closedByServer      = "server"
	closedByTunnelError = "tunnel_error"
	closedByTimeout     = "timeout"
)

// copyResult is how one direction of a relay ended: what it carried, and the
// error, with whether it came from reading the source or writing the
// destination.
type copyResult struct {
	n       int64
	err     error
	reading bool
}

// relayClosedBy names who ended a relay from its first direction to end. up
// is the application to the tunnel.
func relayClosedBy(first copyResult, up bool) string {
	switch {
	case first.err == nil:
		if up {
			return closedByApp
		}
		return closedByServer
	case isTimeout(first.err):
		return closedByTimeout
	case first.reading == up:
		// The application's own socket failed.
		return closedByApp
	}
	return closedByTunnelError
}

// logTCPClosed writes the one line of a relayed connection, at Warn when the
// tunnel, not either end, ended it. A request the server refused gets the
// same line with its reply code.
func logTCPClosed(id, dest string, cfg clientParams, setup, dur time.Duration, up, down int64, closedBy string, err error, extra ...any) {
	level := slog.LevelInfo
	attrs := []any{
		"conn", id,
		"dest", dest,
		"server", cfg.ServerAddr,
		"transport", cfg.effectiveTransport(),
		"setup_ms", setup.Milliseconds(),
		"dur_ms", dur.Milliseconds(),
		"up", up,
		"down", down,
		"closed_by", closedBy,
	}
	if closedBy == closedByTunnelError || closedBy == closedByTimeout {
		level = slog.LevelWarn
		attrs = append(attrs, "error", err)
	}
	slog.Log(context.Background(), level, "TCP Tunnel closed", append(attrs, extra...)...)
}

// minuteCounts is what the client did in one minute, written as one line and
// only for a minute that had something in it.
type minuteCounts struct {
	closed [4]atomic.Int64 // by closedByIndex
	failed atomic.Int64
	// failedBy counts failures by tunnel phase.
	failedBy [7]atomic.Int64
	udp      atomic.Int64
	open     atomic.Int64
}

var minutes minuteCounts

var closedByNames = [...]string{closedByApp, closedByServer, closedByTunnelError, closedByTimeout}

var phaseNames = [...]tunnelPhase{phaseDial, phaseGreeting, phaseAuth, phaseAuthRejected, phaseConnect, phaseConnectReply, ""}

func (m *minuteCounts) tcpClosed(by string) {
	for i, name := range closedByNames {
		if name == by {
			m.closed[i].Add(1)
			return
		}
	}
}

func (m *minuteCounts) setupFailed(phase tunnelPhase) {
	m.failed.Add(1)
	for i, name := range phaseNames {
		if name == phase {
			m.failedBy[i].Add(1)
			return
		}
	}
	m.failedBy[len(phaseNames)-1].Add(1)
}

// emit writes the minute's line and starts the next minute.
func (m *minuteCounts) emit(boot string) {
	attrs := []any{"event", eventMinute, "boot", boot}
	var total int64
	closed := make([]any, 0, 2*len(closedByNames))
	for i, name := range closedByNames {
		if n := m.closed[i].Swap(0); n > 0 {
			closed = append(closed, name, n)
			total += n
		}
	}
	failed := m.failed.Swap(0)
	phases := make([]any, 0, 2*len(phaseNames))
	for i, name := range phaseNames {
		if n := m.failedBy[i].Swap(0); n > 0 {
			label := string(name)
			if label == "" {
				label = "other"
			}
			phases = append(phases, label, n)
		}
	}
	udp := m.udp.Swap(0)
	if total == 0 && failed == 0 && udp == 0 {
		return
	}
	attrs = append(attrs, "tcp_closed", total)
	if len(closed) > 0 {
		attrs = append(attrs, slog.Group("closed_by", closed...))
	}
	attrs = append(attrs, "setup_failed", failed)
	if len(phases) > 0 {
		attrs = append(attrs, slog.Group("failed_phase", phases...))
	}
	attrs = append(attrs, "udp_closed", udp, "open", m.open.Load())
	slog.Info("Minute summary", attrs...)
}

func (m *minuteCounts) run(ctx context.Context, boot string) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.emit(boot)
		}
	}
}
