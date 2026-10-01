// Package signals names the process signals S5Core listens for, one set per
// platform.
//
// It exists because the names are not portable and the build does not say so
// until it is asked: syscall.SIGUSR1 does not exist on Windows, and both
// binaries used it directly. Linux CI never saw it, so the failure surfaced
// in the release workflow, where the Windows build runs after the Docker
// image has already been pushed (F09 in
// docs/reports/code-quality-audit-2026-09-20.md).
//
// The lists are per platform and may be empty. Notify is the only way they
// are used, because signal.Notify with no signals means "every signal", and a
// platform with nothing to listen for would otherwise start listening for
// everything.
package signals

import (
	"context"
	"os"
	"os/signal"
)

// Notify asks for the given signals on ch and reports whether it asked for
// anything. An empty list asks for nothing at all.
func Notify(ch chan<- os.Signal, sigs ...os.Signal) bool {
	if len(sigs) == 0 {
		return false
	}
	signal.Notify(ch, sigs...)
	return true
}

// Action is what to do on any of Signals.
type Action struct {
	Signals []os.Signal
	Do      func()
}

// Handle runs each action on its own goroutine until ctx ends, so a slow
// reload does not hold up a debug toggle. An action whose list is empty on
// this platform starts nothing. The subscription outlives ctx on purpose: a
// SIGHUP during shutdown would otherwise get its default action and kill the
// process in the middle of draining connections and the final traffic flush.
func Handle(ctx context.Context, actions ...Action) {
	for _, a := range actions {
		ch := make(chan os.Signal, 1)
		if !Notify(ch, a.Signals...) {
			continue
		}
		go func(do func()) {
			for {
				select {
				case <-ch:
					do()
				case <-ctx.Done():
					return
				}
			}
		}(a.Do)
	}
}
