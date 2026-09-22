package obfs

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"testing"
)

type perfCountWriter struct {
	calls, bytes int
	io.Writer
}

func (w *perfCountWriter) Write(p []byte) (int, error) {
	w.calls++
	w.bytes += len(p)
	return w.Writer.Write(p)
}
func TestPerfRelayReadGranularity(t *testing.T) {
	raw := &observerPerfConn{}
	payload := benchPayload(1 << 20)
	cfg := Config{PSK: []byte(benchPSK), MTU: 1400, MaxPadding: 256}
	sender, e := NewClientConn(raw, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	for i := 0; i < len(payload); i += 32768 {
		if _, e = sender.Write(payload[i : i+32768]); e != nil {
			t.Fatal(e)
		}
	}
	sender.(interface{ CloseWrite() error }).CloseWrite()
	receiver, e := NewServerConn(raw, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	hash := sha256.New()
	out := &perfCountWriter{Writer: hash}
	n, e := io.CopyBuffer(out, receiver, make([]byte, 32768))
	expected := sha256.Sum256(payload)
	if e != nil || n != int64(len(payload)) || !bytes.Equal(hash.Sum(nil), expected[:]) {
		t.Fatal(n, e)
	}
	t.Logf("payload=%d destination_writes=%d mean_payload_per_write=%.1f", n, out.calls, float64(n)/float64(out.calls))
	if out.calls > 160 {
		t.Fatalf("buffered frames were not combined: %d writes", out.calls)
	}
}

type observerPerfConn struct {
	bytes.Buffer
	discardConn
}

type chunkReadConn struct {
	discardConn
	input      *bytes.Reader
	chunk      int
	finalError bool
}

func (c *chunkReadConn) Read(p []byte) (int, error) {
	if c.chunk > 0 && len(p) > c.chunk {
		p = p[:c.chunk]
	}
	n, err := c.input.Read(p)
	if c.finalError && c.input.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func TestCoalescedReadBoundaries(t *testing.T) {
	for _, chunk := range []int{1, 2, 127, 32768} {
		for _, size := range []int{1, 2, 127, 32768} {
			t.Run(fmt.Sprintf("wire%d/read%d", chunk, size), func(t *testing.T) {
				raw := &observerPerfConn{}
				cfg := Config{PSK: []byte(benchPSK), MaxPadding: 256, Hello: &Hello{Version: "test"}}
				s, err := NewClientConn(raw, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				payload := benchPayload(8192)
				if _, err = s.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err = s.(*conn).writeKeepalive(); err != nil {
					t.Fatal(err)
				}
				if _, err = s.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err = s.(*conn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				seen := 0
				cfg.Hello = nil
				cfg.OnHello = func(Hello) { seen++ }
				r, err := NewServerConn(&chunkReadConn{input: bytes.NewReader(raw.Bytes()), chunk: chunk, finalError: true}, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if n, err := r.Read(nil); n != 0 || err != nil {
					t.Fatal(n, err)
				}
				var out bytes.Buffer
				buf := make([]byte, size)
				for {
					n, err := r.Read(buf)
					out.Write(buf[:n])
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil || n == 0 {
						t.Fatal(n, err)
					}
				}
				if !bytes.Equal(out.Bytes(), bytes.Repeat(payload, 2)) || seen != 1 {
					t.Fatal("payload or control delivery mismatch")
				}
				if n, err := r.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatal(n, err)
				}
			})
		}
	}
}

func TestCoalescedTerminalError(t *testing.T) {
	for _, failure := range []string{"fin", "tag", "kind", "truncated", "wire-eof"} {
		for _, consumer := range []string{"read", "copy", "full", "bufio"} {
			t.Run(failure+"/"+consumer, func(t *testing.T) {
				raw := &observerPerfConn{}
				cfg := Config{PSK: []byte(benchPSK)}
				s, err := NewClientConn(raw, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				payload := []byte("valid bytes before termination")
				if _, err := s.Write(payload); err != nil {
					t.Fatal(err)
				}
				boundary := raw.Len()
				sc := s.(*conn)
				switch failure {
				case "fin":
					err = sc.CloseWrite()
				case "kind":
					err = sc.writeControlLocked(frameKind(255))
				case "tag", "truncated":
					_, err = s.Write([]byte("bad frame"))
				}
				if err != nil {
					t.Fatal(err)
				}
				wire := bytes.Clone(raw.Bytes())
				if failure == "tag" {
					wire[len(wire)-1] ^= 1
				}
				if failure == "truncated" {
					wire = wire[:boundary+9]
				}
				if failure == "tag" || failure == "kind" {
					before := raw.Len()
					if _, err := s.Write([]byte("must never escape")); err != nil {
						t.Fatal(err)
					}
					wire = append(wire, raw.Bytes()[before:]...)
				}
				r, err := NewServerConn(&chunkReadConn{input: bytes.NewReader(wire), finalError: true}, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				var got []byte
				switch consumer {
				case "read":
					buf := make([]byte, 32768)
					n, e := r.Read(buf)
					got, err = buf[:n], e
					if err == nil {
						_, err = r.Read(buf)
					}
				case "copy":
					var out bytes.Buffer
					_, err = io.Copy(&out, r)
					got = out.Bytes()
				case "full":
					buf := make([]byte, len(payload)+1)
					n, e := io.ReadFull(r, buf)
					got, err = buf[:n], e
				case "bufio":
					got, err = io.ReadAll(bufio.NewReader(r))
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("got %q, error %v", got, err)
				}
				if (failure == "fin" || failure == "wire-eof") && (consumer == "copy" || consumer == "bufio") && err != nil {
					t.Fatalf("clean EOF did not finish copy: %v", err)
				}
				if failure != "fin" && failure != "wire-eof" && err == nil {
					t.Fatal("lost terminal error")
				}
				if failure == "truncated" && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
				buf := make([]byte, 1)
				if n, e := r.Read(buf); n != 0 || e == nil {
					t.Fatalf("read after terminal error: %d %v", n, e)
				}
			})
		}
	}
}

func (c *observerPerfConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *observerPerfConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }

type perfGuardConn struct {
	discardConn
	input      *bytes.Reader
	emptyReads int
}

func (c *perfGuardConn) Read(p []byte) (int, error) {
	if c.input.Len() == 0 {
		c.emptyReads++
		return 0, errors.New("unexpected network read after buffered payload")
	}
	return c.input.Read(p)
}
func TestPerfBufferedDataDoesNotWaitForNextFrame(t *testing.T) {
	for _, prefix := range []int{0, 1, 2, 9} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			raw := &observerPerfConn{}
			cfg := Config{PSK: []byte(benchPSK), MTU: 1400, MaxPadding: 256}
			sender, e := NewClientConn(raw, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			first := []byte("deliver this immediately")
			if _, e = sender.Write(first); e != nil {
				t.Fatal(e)
			}
			boundary := raw.Len()
			if _, e = sender.Write([]byte("the next frame is deliberately incomplete")); e != nil {
				t.Fatal(e)
			}
			guarded := &perfGuardConn{input: bytes.NewReader(raw.Bytes()[:boundary+prefix])}
			receiver, e := NewServerConn(guarded, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer receiver.Close()
			out := make([]byte, 32768)
			n, e := receiver.Read(out)
			if e != nil || !bytes.Equal(out[:n], first) || guarded.emptyReads != 0 {
				t.Fatalf("n=%d err=%v extra_reads=%d payload=%q", n, e, guarded.emptyReads, out[:n])
			}
		})
	}
}
