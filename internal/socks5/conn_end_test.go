package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"

	"github.com/mazixs/S5Core/internal/relay"
)

// Every error a handler returns lands on a name from the closed set, and a
// refused login keeps no name at all.
func TestTheEndOfAConnectionHasAClosedName(t *testing.T) {
	for _, c := range []struct {
		err           error
		result, stage string
	}{
		{nil, ResultOK, ""},
		{errors.New("eof"), ResultError, ""},
		{&ConnError{Stage: "auth", Kind: FailureAuth}, ResultAuthFailed, "auth"},
		{&ConnError{Stage: "greeting", Kind: FailureAuth}, ResultAuthFailed, "greeting"},
		{&ConnError{Stage: "greeting", Kind: FailureProtocol}, ResultError, "greeting"},
		{&ConnError{Stage: "request", Op: "rules", Kind: FailurePolicy}, ResultRulesDenied, "request"},
		{&ConnError{Stage: "request", Op: "private_dest", Kind: FailurePolicy}, ResultPrivateDest, "request"},
		{&ConnError{Stage: "request", Op: "reply_write"}, ResultReplyFailed, "request"},
		{&ConnError{Stage: "dial", Op: "resolve"}, ResultResolveFailed, "dial"},
		{&ConnError{Stage: "dial", Err: syscall.ECONNREFUSED}, ResultDialRefused, "dial"},
		{&ConnError{Stage: "dial", Err: syscall.ENETUNREACH}, ResultDialUnreachable, "dial"},
		{&ConnError{Stage: "dial", Err: syscall.EHOSTUNREACH}, ResultDialUnreachable, "dial"},
		{&ConnError{Stage: "dial", Err: os.ErrDeadlineExceeded}, ResultDialTimeout, "dial"},
		{&ConnError{Stage: "dial", Err: context.Canceled}, ResultShutdown, "dial"},
		{fmt.Errorf("wrapped: %w", &ConnError{Stage: "relay", Kind: FailurePolicy}), ResultAccount, ""},
		{&ConnError{Stage: "relay", Kind: FailureCanceled}, ResultShutdown, ""},
		{&ConnError{Stage: "relay", Kind: FailureNetwork}, ResultOK, ""},
	} {
		e := &ConnEnd{Account: "alice", Auth: AuthPassword}
		e.finish(c.err)
		if e.Result != c.result || e.Stage != c.stage {
			t.Errorf("%v: %s/%s, want %s/%s", c.err, e.Result, e.Stage, c.result, c.stage)
		}
		if !slices.Contains(Results(), e.Result) {
			t.Errorf("%v: %q is outside the closed set", c.err, e.Result)
		}
		if c.result == ResultAuthFailed && (e.Account != AccountUnknown || e.Auth != "") {
			t.Errorf("a refused login kept %q/%q", e.Account, e.Auth)
		}
	}
}

func TestWhoEndedARelayIsAClosedName(t *testing.T) {
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	for _, c := range []struct {
		r               relay.Result
		grace, canceled bool
		want            string
	}{
		{relay.Result{ToDestination: true}, false, false, ClosedByClient},
		{relay.Result{}, false, false, ClosedByTarget},
		{relay.Result{Err: timeout}, false, false, ClosedByServerTimeout},
		{relay.Result{Err: syscall.ECONNRESET}, false, false, ClosedByReset},
		{relay.Result{Err: ErrSessionNotAllowed}, false, false, ClosedByAccount},
		{relay.Result{ToDestination: true}, true, false, ClosedByAccount},
		{relay.Result{Err: syscall.ECONNRESET}, false, true, ClosedByShutdown},
	} {
		got := relayClosedBy(c.r, c.grace, c.canceled)
		if got != c.want || !slices.Contains(ClosedBys(), got) {
			t.Errorf("%+v grace=%v canceled=%v: %q, want %q", c.r, c.grace, c.canceled, got, c.want)
		}
	}
}

// The recorder sees the sockets of a dial without changing it: a backup
// that won is named, the first attempt that lost is not counted twice, and
// the address that answered becomes the destination.
func TestTheDialRecorderCountsBackups(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var rec dialRecorder
	calls := 0
	dial := rec.wrap(func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
		}
		return a, nil
	})
	_, _ = dial(context.Background(), "tcp", "[2001:db8::1]:443")
	c, _ := dial(context.Background(), "tcp", "[2001:db8::1]:443")
	failed := rec.wrap(func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	_, _ = failed(context.Background(), "tcp", "192.0.2.1:443")

	var e ConnEnd
	rec.settle(&e, c, "example.test:443", 0)
	if e.DialTries != 2 || e.DialBackups != 1 || !e.DialBackupWon {
		t.Fatalf("tries %d backups %d won %v", e.DialTries, e.DialBackups, e.DialBackupWon)
	}
	if e.Dst.String() != "[2001:db8::1]:443" {
		t.Errorf("dst %v", e.Dst)
	}
	want := []DialOutcome{{V6: true, Outcome: DialOKBackup}, {V6: false, Outcome: DialRefused}}
	if !slices.Equal(e.DialOutcomes, want) {
		t.Errorf("outcomes %+v", e.DialOutcomes)
	}
	for _, o := range e.DialOutcomes {
		if !slices.Contains(DialOutcomes(), o.Outcome) {
			t.Errorf("%q is outside the closed set", o.Outcome)
		}
	}
}

func TestEveryCommandHasAKind(t *testing.T) {
	for _, cmd := range []uint8{ConnectCommand, BindCommand, AssociateCommand, UDPTunnelCommand, UDPNativeCommand, 0x42} {
		e := &ConnEnd{Command: commandName(cmd)}
		if !slices.Contains(Commands(), e.Command) || !slices.Contains(Kinds(), e.Kind()) {
			t.Errorf("command %#x: %q/%q", cmd, e.Command, e.Kind())
		}
	}
	for _, c := range []struct {
		rotations int64
		answered  bool
		want      string
	}{
		{0, false, ""},
		{2, true, RotationAnswered},
		{udpRotateMax, false, RotationGaveUp},
		{1, false, RotationClosed},
	} {
		e := &ConnEnd{Rotations: c.rotations, Answered: c.answered}
		if got := e.RotationOutcome(); got != c.want {
			t.Errorf("%d/%v: %q, want %q", c.rotations, c.answered, got, c.want)
		}
	}
}
