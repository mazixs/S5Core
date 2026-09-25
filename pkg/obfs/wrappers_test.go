package obfs

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

type keyedLayer struct {
	net.Conn
	keys veil.DatagramKeys
}

func (k keyedLayer) DatagramKeys() (veil.DatagramKeys, error) { return k.keys, nil }
func (k keyedLayer) Identity() string                         { return "alice" }

type netConnWrapper struct{ net.Conn }

func (w netConnWrapper) NetConn() net.Conn { return w.Conn }

type unwrapWrapper struct{ net.Conn }

func (w unwrapWrapper) Unwrap() net.Conn { return w.Conn }

type selfWrapper struct{ net.Conn }

func (w *selfWrapper) NetConn() net.Conn { return w }

// The datagram keys and the identity are found through the same wrappers. A
// wrapper that only has Unwrap turned native UDP off, and one that returned
// itself hung the connection's goroutine.
func TestDatagramKeysAreFoundThroughEveryWrapper(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var want veil.DatagramKeys
	want.SendTag[0] = 7
	layer := keyedLayer{Conn: a, keys: want}
	for name, c := range map[string]net.Conn{
		"NetConn":         netConnWrapper{layer},
		"Unwrap":          unwrapWrapper{layer},
		"Unwrap, NetConn": unwrapWrapper{netConnWrapper{layer}},
	} {
		keys, err := DatagramKeysOf(c)
		if err != nil || keys.SendTag != want.SendTag {
			t.Errorf("%s: keys %v, %v", name, keys.SendTag[0], err)
		}
		if id := IdentityOf(c); id != "alice" {
			t.Errorf("%s: identity %q", name, id)
		}
	}

	done := make(chan error, 1)
	go func() {
		_, err := DatagramKeysOf(&selfWrapper{Conn: a})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoDatagramKeys) {
			t.Fatalf("a wrapper that returns itself: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a wrapper that returns itself hung the walk")
	}
	if _, err := DatagramKeysOf(netConnWrapper{a}); !errors.Is(err, ErrNoDatagramKeys) {
		t.Fatalf("no obfs layer: %v", err)
	}
}
