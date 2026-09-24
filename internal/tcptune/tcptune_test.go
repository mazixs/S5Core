package tcptune

import (
	"errors"
	"net"
	"testing"
)

type netConnWrapper struct{ net.Conn }

func (w netConnWrapper) NetConn() net.Conn { return w.Conn }

type unwrapWrapper struct{ net.Conn }

func (w unwrapWrapper) Unwrap() net.Conn { return w.Conn }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func TestTheWalkReachesTheSocketThroughEveryWrapper(t *testing.T) {
	c, _ := tcpPair(t)
	wrapped := netConnWrapper{unwrapWrapper{netConnWrapper{c}}}
	sc, err := Socket(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if sc != c {
		t.Fatalf("walk stopped at %T, not at the socket", sc)
	}
}

func TestAPipeHasNoSocket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := ForDatagrams(netConnWrapper{a}); !errors.Is(err, ErrNoSocket) {
		t.Fatalf("got %v, want ErrNoSocket", err)
	}
}

func TestAWrapperCycleEnds(t *testing.T) {
	var loop cycle
	loop.next = &loop
	if _, err := Socket(&loop); !errors.Is(err, ErrNoSocket) {
		t.Fatalf("got %v, want ErrNoSocket", err)
	}
}

type cycle struct {
	net.Conn
	next *cycle
}

func (c *cycle) NetConn() net.Conn { return c.next }
