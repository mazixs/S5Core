package diagnostics

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeConn is a connection the walk takes for a socket, with a kernel that
// says nothing: its SyscallConn fails. Its calls take the delays it is given.
type fakeConn struct {
	readDelay, writeDelay atomic.Int64
	deadline              time.Time
	closed                atomic.Int32
}

func (c *fakeConn) Read(p []byte) (int, error) {
	time.Sleep(time.Duration(c.readDelay.Load()))
	return len(p), nil
}

func (c *fakeConn) Write(p []byte) (int, error) {
	time.Sleep(time.Duration(c.writeDelay.Load()))
	return len(p), nil
}

func (c *fakeConn) Close() error                       { c.closed.Add(1); return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080} }
func (c *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (c *fakeConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *fakeConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("no kernel in this test")
}

type fakeHalfConn struct {
	fakeConn
	halfClosed bool
}

func (c *fakeHalfConn) CloseWrite() error { c.halfClosed = true; return nil }

// testRecorder installs a recorder for the test. Inside a synctest bubble it
// must be made in the bubble, so its start is on the bubble's clock.
func testRecorder(t testing.TB) *recorder {
	t.Helper()
	r := newRecorder()
	if !current.CompareAndSwap(nil, r) {
		t.Fatal("a recorder is running already")
	}
	t.Cleanup(func() { current.CompareAndSwap(r, nil) })
	return r
}

// records is what the ring holds.
func (r *recorder) records() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	got, _ := r.ring.copyAfter(0, make([]record, 0, ringRecords))
	return got
}

func ofKind(recs []record, k kind) []record {
	var out []record
	for _, rec := range recs {
		if rec.kind == k {
			out = append(out, rec)
		}
	}
	return out
}
