package main

import (
	"net"
	"strings"
	"testing"
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

type shapeWriteRecorder struct {
	net.Conn // Only Write is used by the shape.
	writes   []string
}

func (c *shapeWriteRecorder) Write(p []byte) (int, error) {
	c.writes = append(c.writes, string(p))
	return len(p), nil
}

// Check the writes themselves: TCP reads need not preserve their boundaries.
func TestASplitShapeLeavesInSeveralWrites(t *testing.T) {
	s, err := parseShape("random:split3")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{strings.Repeat("a", 100), strings.Repeat("b", 100), strings.Repeat("c", 100)}
	s.build = func(int) []byte { return []byte(strings.Join(want, "")) }

	var conn shapeWriteRecorder
	if err := s.write(&conn, 300, 0); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != len(want) {
		t.Fatalf("split3 made %d writes, want %d", len(conn.writes), len(want))
	}
	for i, got := range conn.writes {
		if got != want[i] {
			t.Errorf("write %d = %q, want %q", i+1, got, want[i])
		}
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
