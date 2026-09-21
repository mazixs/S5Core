package main

import (
	"net"
	"testing"
	"time"
)

// The shape spelling is the probe's whole interface: a run is only worth
// anything if the name in the report is the thing that went on the wire.
func TestAShapeSpellingIsReadAsWritten(t *testing.T) {
	tests := []struct {
		spec       string
		wantSplits int
		wantSize   int
	}{
		{"random", 0, 0},
		{"random:split2", 2, 0},
		{"tls:split3@512", 3, 512},
		{"print6@64", 0, 64},
		{"http:split4", 4, 0},
	}
	for _, tt := range tests {
		s, err := parseShape(tt.spec)
		if err != nil {
			t.Errorf("%s: %v", tt.spec, err)
			continue
		}
		if s.name != tt.spec {
			t.Errorf("%s: the report would call it %q", tt.spec, s.name)
		}
		if s.splits != tt.wantSplits {
			t.Errorf("%s: splits = %d, want %d", tt.spec, s.splits, tt.wantSplits)
		}
		if s.size != tt.wantSize {
			t.Errorf("%s: size = %d, want %d", tt.spec, s.size, tt.wantSize)
		}
	}

	for _, bad := range []string{"random:split0", "random:pad2", "random@0", "nosuch", "random:split"} {
		if _, err := parseShape(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A split shape has to arrive as several writes, or the measurement is a
// measurement of nothing. Loopback keeps the boundaries when the reader
// keeps up, which is what makes this checkable without a packet capture.
func TestASplitShapeLeavesInSeveralWrites(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reads := make(chan []int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			reads <- nil
			return
		}
		defer conn.Close()
		var sizes []int
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				sizes = append(sizes, n)
			}
			if err != nil {
				break
			}
		}
		reads <- sizes
	}()

	s, err := parseShape("random:split3")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.write(conn, 300, 3*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	sizes := <-reads
	if len(sizes) != 3 {
		t.Fatalf("split3 arrived as %v, want three writes", sizes)
	}
	total := 0
	for _, n := range sizes {
		total += n
	}
	if total != 300 {
		t.Errorf("split3 delivered %d bytes, want 300", total)
	}
}

// One write stays one write: the modifier is opt-in, and a shape without it
// must keep measuring what it measured before.
func TestAnUnsplitShapeIsStillOneWrite(t *testing.T) {
	s, err := parseShape("random")
	if err != nil {
		t.Fatal(err)
	}
	if s.splits >= 2 {
		t.Fatalf("a bare shape carries %d splits", s.splits)
	}
	if got := s.sizeFor(256); got != 256 {
		t.Errorf("a bare shape overrode -size with %d", got)
	}
}
