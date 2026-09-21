package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// The transport advice is the one setting whose whole value is in changing on
// a running server: moving a fleet between transports is supposed to be one
// edit and one signal, not a release (plan task Ф5-7,
// docs/field/migration.md). TRANSPORT_ADVICE alone could not deliver that.
// The environment of a running process cannot be changed from outside it, so
// the SIGHUP handler re-parsed the same variables the process started with
// and applied the value it already had - the documented promise was
// unkeepable by construction (audit finding F19).
//
// TRANSPORT_ADVICE_FILE is the changeable source, and it is the same shape as
// LOG_LEVEL_FILE, which exists for the same reason: the file wins over the
// variable when it is set, and SIGHUP re-reads it. The variable stays for
// deployments that set the advice once and restart to change it.

// maxAdviceFileBytes bounds the read. The reload runs on the signal
// goroutine, so a path that never ends - a fifo, /dev/zero, a file someone is
// still writing - would not just fail, it would stop every later SIGHUP from
// being handled at all.
const maxAdviceFileBytes = 4 << 10

// adviceFromFile reads the advice text from path. A missing file is not an
// error and means no advice: that is what an unset variable means too, and it
// is how an operator withdraws a recommendation without editing the unit
// file.
func adviceFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	b, err := io.ReadAll(io.LimitReader(f, maxAdviceFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxAdviceFileBytes {
		return "", fmt.Errorf("%s is larger than %d bytes, which no advice is", path, maxAdviceFileBytes)
	}

	text := strings.TrimSpace(string(b))
	if strings.ContainsAny(text, "\r\n") {
		// Two lines are two recommendations, and joining them would build a
		// third that the operator never wrote.
		return "", fmt.Errorf("%s holds more than one line: an advice is one line, as TRANSPORT_ADVICE is", path)
	}
	return text, nil
}

// resolveTransportAdvice puts the effective advice into cfg, from the file if
// one is configured. It is called on startup and again on every SIGHUP, so
// that the value the server validates is the value the operator last wrote.
func resolveTransportAdvice(cfg *params) error {
	if cfg.TransportAdviceFile == "" {
		return nil
	}
	text, err := adviceFromFile(cfg.TransportAdviceFile)
	if err != nil {
		return fmt.Errorf("TRANSPORT_ADVICE_FILE: %w", err)
	}
	cfg.TransportAdvice = text
	return nil
}
