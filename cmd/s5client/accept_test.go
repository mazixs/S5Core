package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type exhaustedListener struct {
	net.Listener
	calls int
	err   error
}

func (l *exhaustedListener) Accept() (net.Conn, error) { l.calls++; return nil, l.err }

func TestAcceptExhaustionBacksOffAndShutdownInterruptsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ln := &exhaustedListener{err: &net.OpError{Op: "accept", Err: syscall.EMFILE}}
		done := make(chan error, 1)
		go func() { _, err := acceptWithBackoff(ctx, ln); done <- err }()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if ln.calls > 12 || ln.calls < 8 {
			t.Fatalf("accept calls in 3s: %d", ln.calls)
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		default:
			t.Fatal("shutdown waited for backoff")
		}
	})
}

func TestAcceptDoesNotRetryPermanentFailure(t *testing.T) {
	ln := &exhaustedListener{err: errors.New("permanent")}
	_, err := acceptWithBackoff(context.Background(), ln)
	if !errors.Is(err, ln.err) || ln.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, ln.calls)
	}
}

func TestSilentLocalClientHasHandshakeDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() { handleClient(server, clientParams{HandshakeTimeout: time.Second}, nil); close(done) }()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("silent client retained connection")
		}
	})
}
