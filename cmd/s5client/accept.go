package main

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/mazixs/S5Core/internal/acceptretry"
)

// Resource exhaustion must not turn into a CPU and log-writing loop. A
// successful accept resets the delay; shutdown interrupts even the longest wait.
func acceptWithBackoff(ctx context.Context, listener net.Listener) (net.Conn, error) {
	delay := acceptretry.Next(0)
	var logged time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := listener.Accept()
		if err == nil || !acceptretry.Recoverable(err) {
			return c, err
		}
		if time.Since(logged) >= time.Second {
			slog.Warn("Accept failed, retrying", "error", err, "retry_in", delay)
			logged = time.Now()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		delay = acceptretry.Next(delay)
	}
}
