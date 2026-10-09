package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// A client may open a transport ahead of need and close it unused (plan task
// R4-9). The server must count that apart from the refusals and must not
// drain it; everything else that ends before the first frame keeps its old
// classification and its drain.

// readsCounted is a server transport that counts its reads. The drain is
// the only thing that reads again after the opening failed, so the count is
// what tells a drained connection from one that was not: on a peer that is
// gone the drain ends at once and the time it takes says nothing.
type readsCounted struct {
	net.Conn
	err   error // when set, every read fails with it
	reads int
}

func (c *readsCounted) Read(p []byte) (int, error) {
	c.reads++
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// endOf runs one server connection over conn and reports what the observer
// saw, what Read returned and how long Read took.
func endOf(t *testing.T, conn net.Conn) (seen []FailureReason, took time.Duration, err error) {
	t.Helper()
	server, nerr := NewServerConn(conn, Config{
		PSK:          bytes.Repeat([]byte("k"), 32),
		RefuseLinger: 7 * time.Second,
		MTU:          1400,
		OnFailure:    func(fe *FrameError) { seen = append(seen, fe.Reason) },
	})
	if nerr != nil {
		t.Fatalf("server conn: %v", nerr)
	}
	start := time.Now()
	_, err = server.Read(make([]byte, 64))
	took = time.Since(start)
	_ = server.Close()
	return seen, took, err
}

func TestAConnectionClosedBeforeItsFirstByteIsAnIdleClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		_ = clientSide.Close()
		conn := &readsCounted{Conn: serverSide}

		seen, _, err := endOf(t, conn)
		if len(seen) != 1 || seen[0] != ReasonIdleClose {
			t.Fatalf("observer saw %v, want exactly [%s]", seen, ReasonIdleClose)
		}
		if _, wrapped := ReasonOf(err); wrapped || !errors.Is(err, io.EOF) {
			t.Fatalf("Read = %v, want a bare io.EOF: io.Copy compares with ==", err)
		}
		if conn.reads != 1 {
			t.Fatalf("the transport was read %d times, want 1: an idle close is not drained", conn.reads)
		}
	})
}

func TestAWebSocketPeerThatHangsUpUnusedIsAnIdleClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		defer func() { _ = clientSide.Close() }()
		hungUp := errors.New("websocket: close 1006 (abnormal closure): unexpected EOF")
		conn := &readsCounted{Conn: serverSide, err: hungUp}

		seen, _, err := endOf(t, conn)
		if len(seen) != 1 || seen[0] != ReasonIdleClose {
			t.Fatalf("observer saw %v, want exactly [%s]", seen, ReasonIdleClose)
		}
		if reason, ok := ReasonOf(err); !ok || reason != ReasonIdleClose {
			t.Fatalf("ReasonOf(%v) = %q, %v; want %q", err, reason, ok, ReasonIdleClose)
		}
		if conn.reads != 1 {
			t.Fatalf("the transport was read %d times, want 1", conn.reads)
		}
	})
}

func TestASilentPeerThatStaysIsNotAnIdleClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		defer func() { _ = clientSide.Close() }()
		_ = serverSide.SetReadDeadline(time.Now().Add(time.Second))

		seen, took, _ := endOf(t, serverSide)
		if len(seen) != 1 || seen[0] != ReasonEOFBeforeFrame {
			t.Fatalf("observer saw %v, want exactly [%s]: the peer did not leave, the server's budget ran out", seen, ReasonEOFBeforeFrame)
		}
		if want := time.Second + 7*time.Second; took != want {
			t.Fatalf("a silent peer was held for %v, want %v (deadline, then the drain)", took, want)
		}
	})
}

func TestAPeerThatSentAByteIsNotAnIdleClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		go func() {
			_, _ = clientSide.Write([]byte{0x42})
			_ = clientSide.Close()
		}()
		conn := &readsCounted{Conn: serverSide}

		seen, _, err := endOf(t, conn)
		if len(seen) != 1 || seen[0] != ReasonEOFBeforeFrame {
			t.Fatalf("observer saw %v, want exactly [%s]", seen, ReasonEOFBeforeFrame)
		}
		if err == nil {
			t.Fatal("a one-byte opening was accepted")
		}
		// The byte, the end of stream, then the drain's read: the counter
		// does see a drain where there is one.
		if conn.reads != 3 {
			t.Fatalf("the transport was read %d times, want 3 with the drain", conn.reads)
		}
	})
}

func TestOnlyIdleCloseIsNotAFailure(t *testing.T) {
	for _, r := range []FailureReason{
		ReasonEOFBeforeFrame, ReasonShortFrame, ReasonDecryptFail, ReasonReplay,
		ReasonHistoryFull, ReasonBadOpening, ReasonUnknownFrameKind, ReasonBadControl,
	} {
		if !r.IsFailure() {
			t.Errorf("%s is reported as not a failure", r)
		}
	}
	if ReasonIdleClose.IsFailure() {
		t.Errorf("%s is reported as a failure", ReasonIdleClose)
	}
}
