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
