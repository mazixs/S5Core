package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// The knob has to reach the wire, not just the struct. What it changes is the
// size of the first packet: the filter measured in docs/field/stealth.md lets
// through anything below 100 bytes, and the client's usual first write is 125
// and up because it carries the opening, a hello frame and a data frame.
func TestTheSplitOpeningKnobReachesTheWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		split bool
	}{
		{"one write", false},
		{"opening on its own", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := clientParams{
				PSK:          strings.Repeat("k", 32),
				MaxPadding:   256,
				MTU:          1400,
				Prologue:     "printable",
				SplitOpening: tc.split,
			}
			rec := &writeRecorder{}
			tunnel, err := wrapTunnel(rec, cfg)
			if err != nil {
				t.Fatalf("wrapTunnel: %v", err)
			}
			if _, err := tunnel.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				t.Fatalf("write: %v", err)
			}
			if len(rec.sizes) == 0 {
				t.Fatal("the client wrote nothing")
			}
			first := rec.sizes[0]
			switch {
			case tc.split && first >= 100:
				t.Errorf("first packet is %d bytes; with a split opening it is the opening alone, 43-72", first)
			case !tc.split && first < 100:
				t.Errorf("first packet is %d bytes; in one write it carries the opening and the frames", first)
			}
		})
	}
}

// writeRecorder keeps the size of every write and goes nowhere.
type writeRecorder struct {
	sizes []int
}

func (c *writeRecorder) Write(b []byte) (int, error) {
	c.sizes = append(c.sizes, len(b))
	return len(b), nil
}

func (c *writeRecorder) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (c *writeRecorder) Close() error                     { return nil }
func (c *writeRecorder) SetDeadline(time.Time) error      { return nil }
func (c *writeRecorder) SetReadDeadline(time.Time) error  { return nil }
func (c *writeRecorder) SetWriteDeadline(time.Time) error { return nil }
func (c *writeRecorder) LocalAddr() net.Addr              { return nil }
func (c *writeRecorder) RemoteAddr() net.Addr             { return nil }
