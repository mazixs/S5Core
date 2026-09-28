package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestAnAssociationEndIsNamedByItsCause(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, EndedByClient},
		{fmt.Errorf("tcp read length error: %w", io.EOF), EndedByClient},
		{fmt.Errorf("tcp read frame error: %w", io.ErrUnexpectedEOF), EndedByClient},
		{ErrSessionNotAllowed, EndedByAccount},
		{context.Canceled, EndedByShutdown},
		{fmt.Errorf("tcp read length error: %w", &net.OpError{Op: "read", Net: "tcp",
			Err: os.NewSyscallError("read", syscall.ECONNRESET)}), EndedByReset},
		{fmt.Errorf("tcp write error: %w", &net.OpError{Op: "write", Net: "tcp",
			Err: os.NewSyscallError("write", syscall.EPIPE)}), EndedByReset},
		{fmt.Errorf("tcp read frame error: %w", os.ErrDeadlineExceeded), EndedByTimeout},
		{fmt.Errorf("udp socket read error: %w", net.ErrClosed), EndedByError},
		{errors.New("tunnel write: broken"), EndedByError},
	} {
		if got := associationEnd(c.err); got != c.want {
			t.Errorf("associationEnd(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

type associationEnds struct {
	mu   sync.Mutex
	ends [][2]string
	seen chan struct{}
}

func (a *associationEnds) record(kind, reason string) {
	a.mu.Lock()
	a.ends = append(a.ends, [2]string{kind, reason})
	a.mu.Unlock()
	a.seen <- struct{}{}
}

func (a *associationEnds) next(t *testing.T) [2]string {
	t.Helper()
	select {
	case <-a.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("no association end was reported")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ends[len(a.ends)-1]
}

func associationEndServer(t *testing.T) (string, *associationEnds, context.CancelFunc) {
	t.Helper()
	ends := &associationEnds{seen: make(chan struct{}, 8)}
	server, err := New(&Config{
		BindIP:           net.ParseIP("127.0.0.1"),
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnAssociationEnd: ends.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() { _ = server.ServeContext(ctx, ln) }()
	return ln.Addr().String(), ends, cancel
}

// Every association that opened is reported once, by its kind and by who
// ended it, and a CONNECT is not an association at all.
func TestTheEndOfEveryAssociationIsReported(t *testing.T) {
	addr, ends, _ := associationEndServer(t)
	anywhere := []byte{0x01, 0, 0, 0, 0, 0, 0}

	for _, c := range []struct {
		command byte
		kind    string
	}{
		{AssociateCommand, AssociationPlain},
		{UDPTunnelCommand, AssociationTunnel},
	} {
		conn, _ := associateThrough(t, addr, c.command, anywhere)
		_ = conn.Close()
		if got, want := ends.next(t), [2]string{c.kind, EndedByClient}; got != want {
			t.Errorf("command 0x%02x ended as %v, want %v", c.command, got, want)
		}
	}

	// A reset is not a close: an association that lost its connection in the
	// middle of a match says so.
	conn, _ := associateThrough(t, addr, UDPTunnelCommand, anywhere)
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
	if got, want := ends.next(t), [2]string{AssociationTunnel, EndedByReset}; got != want {
		t.Errorf("a reset tunnel ended as %v, want %v", got, want)
	}
	conn, _ = associateThrough(t, addr, AssociateCommand, anywhere)
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
	if got, want := ends.next(t), [2]string{AssociationPlain, EndedByReset}; got != want {
		t.Errorf("a reset association ended as %v, want %v", got, want)
	}
}

func TestAnAssociationTheServerStoppedEndedByShutdown(t *testing.T) {
	addr, ends, stop := associationEndServer(t)
	associateThrough(t, addr, UDPTunnelCommand, []byte{0x01, 0, 0, 0, 0, 0, 0})
	stop()
	if got, want := ends.next(t), [2]string{AssociationTunnel, EndedByShutdown}; got != want {
		t.Errorf("a tunnel of a stopped server ended as %v, want %v", got, want)
	}
}
