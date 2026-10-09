package relay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type abortWrapper struct {
	net.Conn
	self   bool
	closes int
}

func (c *abortWrapper) NetConn() net.Conn {
	if c.self {
		return c
	}
	return c.Conn
}
func (c *abortWrapper) Close() error { c.closes++; return c.Conn.Close() }

func TestAbortUnwrapsTCPAndBoundsMalformedWrapperChains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socket, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &abortWrapper{Conn: socket}
	Abort(wrapper)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = peer.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("aborted stream ended cleanly: %v", err)
	}
	if wrapper.closes != 1 {
		t.Fatal("original wrapper was not closed exactly once")
	}
	for _, self := range []bool{false, true} {
		a, b := net.Pipe()
		defer b.Close()
		w := &abortWrapper{Conn: a, self: self}
		Abort(w)
		if w.closes != 1 {
			t.Fatal("malformed chain skipped original close")
		}
		if _, err = b.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("wrapped pipe still open", err)
		}
	}
}

type partialFailWriter struct{ short bool }

func (w partialFailWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) / 2, nil
	}
	return min(2, len(p)), io.ErrClosedPipe
}

func TestMeteredRelayBillsOnlyWrittenBytesAndAbortsTransportFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		var billed atomic.Int64
		var payload, aborted, closed int64
		h := Half{Src: bytes.NewBufferString("abcd"), Dst: partialFailWriter{short: short}, Counter: &billed, BytesAdd: func(n int64) { payload += n }, AbortDst: func() { aborted++ }, CloseDst: func() { closed++ }}
		err := h.Run()
		want := io.ErrClosedPipe
		if short {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || billed.Load() != 2 || payload != 2 || h.Copied != 2 || aborted != 1 || closed != 0 {
			t.Fatalf("err=%v billed=%d payload=%d copied=%d abort=%d close=%d", err, billed.Load(), payload, h.Copied, aborted, closed)
		}
	}
	var payload, closed int64
	h := Half{Src: bytes.NewBufferString("done"), Dst: io.Discard, BytesAdd: func(n int64) { payload += n }, CloseDst: func() { closed++ }, AbortDst: func() { t.Error("clean stream aborted") }}
	if err := h.Run(); err != nil || payload != 4 || closed != 1 {
		t.Fatal("clean relay lost its billing or FIN", err)
	}
	var aborted bool
	h = Half{Src: io.LimitReader(&failingRelayReader{}, 1), Dst: io.Discard, AbortDst: func() { aborted = true }}
	if err := h.Run(); err == nil || !aborted {
		t.Fatal("unmetered transport failure did not abort")
	}
}

type failingRelayReader struct{}

func (*failingRelayReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
