package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"syscall"
	"time"
)

// Resource exhaustion must not turn into a CPU and log-writing loop. A
// successful accept resets the delay; shutdown interrupts even the longest wait.
func acceptWithBackoff(ctx context.Context, listener net.Listener) (net.Conn, error) {
	delay := 5 * time.Millisecond
	var logged time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := listener.Accept()
		if err == nil || !retryAccept(err) {
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
		delay = min(delay*2, time.Second)
	}
}

func retryAccept(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, errno := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED, syscall.EINTR, syscall.EAGAIN} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
