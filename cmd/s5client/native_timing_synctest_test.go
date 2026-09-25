package main

import (
	"net"
	"slices"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// The moments of the real-socket tests in native_path_linux_test.go, in the
// bubble of native_liveness_synctest_test.go.

// The ICMP test, with its moments. The path is verified at 0 s. At 0.5 s the
// server's port is gone: the datagram sent then and the probe it pokes are
// lost, and the socket reports the error. The port is back at 0.6 s, the probe
// at 0.9 s is answered, and the datagram at 1.7 s goes native although every
// answer from before the error is older than the freshness window: only a
// reader that went on past the error has heard the server since.
func TestAnErrorOnAVerifiedPathKeepsItNative(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(500 * time.Millisecond)
		l.path.dropUp.Store(true)
		if !l.client.carry([]byte("into the void")) {
			t.Fatal("the datagram before the error went by 0x83")
		}
		l.path.errs <- &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
		l.at(600 * time.Millisecond)
		l.path.dropUp.Store(false)
		l.at(1700 * time.Millisecond)
		if !l.client.carry([]byte("input")) {
			t.Fatal("the datagram after the error went by 0x83")
		}
		synctest.Wait()
		if n := l.path.data.Load(); n != 1 {
			t.Fatalf("%d datagrams reached the server natively, want the one after the error", n)
		}
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
	})
}

// The half of TestASparseFlowIsCarriedNatively that the server sees: a flow
// that speaks every 1.5 s, from 0.1 to 7.6 s, never tells the server to answer
// by TCP, and every probe says the client hears it, from the one that follows
// the verification at 0 s to the last of the active flow at 9.6 s. The
// server's answers stay native between the datagrams.
func TestASparseFlowKeepsTheServersAnswersNative(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		for i := 0; i < 6; i++ {
			l.at(100*time.Millisecond + time.Duration(i)*1500*time.Millisecond)
			if !l.client.carry([]byte("input")) {
				t.Fatalf("datagram %d went by 0x83", i)
			}
		}
		l.at(15 * time.Second)
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
		want := []time.Duration{0}
		for at := 400 * time.Millisecond; at <= 9600*time.Millisecond; at += 400 * time.Millisecond {
			want = append(want, at)
		}
		l.path.mu.Lock()
		heard, bare := slices.Clone(l.path.heard), slices.Clone(l.path.bare)
		l.path.mu.Unlock()
		if !slices.Equal(heard, want) {
			t.Fatalf("probes that hear at %v, want %v", heard, want)
		}
		if want := []time.Duration{0}; !slices.Equal(bare, want) {
			t.Fatalf("bare probes at %v, want %v", bare, want)
		}
	})
}
