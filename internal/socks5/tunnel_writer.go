package socks5

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// A native association's control stream carries the datagrams that do not go
// natively, and a write to it can wait for the send buffer. Its frames are
// written by a TunnelWriter, so that the reader that hands datagrams to the
// native path never waits for the stream: it used to write the frames
// itself, and one datagram too big for native held every short one behind it
// (finding F1 of the 2.3.0-rc1 audit, docs/veil-spec.md, 10.6).
const (
	// The queue holds a wave of a game server's answers, some 450 datagrams
	// within 5-10 ms, twice over. The stream takes them more slowly than the
	// reader hands them over, and a queue of 64 dropped part of every wave
	// that went by TCP however healthy the stream was
	// (docs/benchmarks/udp-burst-2026-09-28.md). The age below still bounds
	// how late a frame can be; the bytes are counted by the buffers frames
	// take, so they bound small frames at the same 1024.
	tunnelQueueFrames = 1024
	tunnelQueueBytes  = 2 << 20
	// A frame that waited this long is dropped, as UDP would drop it: a
	// state update this late is worth less than the room it takes.
	tunnelFrameAge = 250 * time.Millisecond
	// Frames of a datagram up to this size take a small buffer, so that a
	// full queue of them holds no 64 KiB buffers.
	tunnelSmallFrame = 2048
)

type tunnelFrame struct {
	buf     []byte
	payload int
	at      time.Time
}

var (
	smallTunnelFrames = sync.Pool{New: func() any { return &tunnelFrame{buf: make([]byte, 0, tunnelSmallFrame)} }}
	bigTunnelFrames   = sync.Pool{New: func() any { return &tunnelFrame{buf: make([]byte, 0, 2+65535)} }}
)

func releaseTunnelFrame(f *tunnelFrame) {
	if cap(f.buf) == tunnelSmallFrame {
		smallTunnelFrames.Put(f)
		return
	}
	bigTunnelFrames.Put(f)
}

// TunnelWriter is the one writer of a stream of 0x83 frames. Submit never
// waits: a frame past the queue is dropped, and one that waited too long is
// dropped when its turn comes. A frame is written whole or not at all, since
// the stream has no way to drop part of one. The control frame (the loss
// signal of a client, the server's answer to it) goes ahead of the queue and
// is built when it is written, so a pending one covers the next.
type TunnelWriter struct {
	w       io.Writer
	control func() []byte
	written func(payload int) error
	frames  chan *tunnelFrame
	queued  atomic.Int64
	pending atomic.Bool
	wake    chan struct{}
	stop    chan struct{}
	stopped sync.Once
	drops   TunnelDrops
	shared  *TunnelDrops
}

// NewTunnelWriter writes to w once Run is called. control builds the control
// frame and runs on the writer's goroutine; written, when set, hears of every
// frame written with the payload the caller gave it, and its error stops the
// writer.
func NewTunnelWriter(w io.Writer, control func() []byte, written func(payload int) error) *TunnelWriter {
	return &TunnelWriter{w: w, control: control, written: written,
		frames: make(chan *tunnelFrame, tunnelQueueFrames), wake: make(chan struct{}, 1), stop: make(chan struct{})}
}

// Submit queues the frame head||body and reports whether it did. Neither is
// kept: both are copied.
func (t *TunnelWriter) Submit(head, body []byte, payload int) bool {
	n := len(head) + len(body)
	pool := &bigTunnelFrames
	if n <= tunnelSmallFrame {
		pool = &smallTunnelFrames
	}
	f := pool.Get().(*tunnelFrame)
	if t.queued.Add(int64(cap(f.buf))) > tunnelQueueBytes {
		t.queued.Add(-int64(cap(f.buf)))
		pool.Put(f)
		t.drop(&t.drops.Queue)
		return false
	}
	f.buf = append(append(f.buf[:0], head...), body...)
	f.payload, f.at = payload, time.Now()
	select {
	case t.frames <- f:
		return true
	default:
		t.queued.Add(-int64(cap(f.buf)))
		pool.Put(f)
		t.drop(&t.drops.Queue)
		return false
	}
}

// Count adds the writer's drops to shared as well. It is called before Run
// and Submit.
func (t *TunnelWriter) Count(shared *TunnelDrops) { t.shared = shared }

func (t *TunnelWriter) drop(own *atomic.Uint64) {
	own.Add(1)
	if t.shared == nil {
		return
	}
	if own == &t.drops.Queue {
		t.shared.Queue.Add(1)
	} else {
		t.shared.Age.Add(1)
	}
}

// Control asks for the control frame to be written before the next queued
// one.
func (t *TunnelWriter) Control() {
	t.pending.Store(true)
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// Dropped is how many frames were not written: past the queue, or too old.
func (t *TunnelWriter) Dropped() uint64 { return t.drops.Queue.Load() + t.drops.Age.Load() }

// Stop ends Run, which returns nil. Frames still queued are not written.
func (t *TunnelWriter) Stop() { t.stopped.Do(func() { close(t.stop) }) }

// Run writes until Stop, a failed write or an error of written.
func (t *TunnelWriter) Run() error {
	defer t.drain()
	for {
		if t.pending.Swap(false) {
			if _, err := t.w.Write(t.control()); err != nil {
				return fmt.Errorf("tunnel write: %w", err)
			}
			continue
		}
		select {
		case <-t.stop:
			return nil
		case <-t.wake:
		case f := <-t.frames:
			t.queued.Add(-int64(cap(f.buf)))
			if time.Since(f.at) > tunnelFrameAge {
				t.drop(&t.drops.Age)
				releaseTunnelFrame(f)
				continue
			}
			_, err := t.w.Write(f.buf)
			payload := f.payload
			releaseTunnelFrame(f)
			if err != nil {
				return fmt.Errorf("tunnel write: %w", err)
			}
			if t.written != nil {
				if err := t.written(payload); err != nil {
					return err
				}
			}
		}
	}
}

func (t *TunnelWriter) drain() {
	for {
		select {
		case f := <-t.frames:
			t.queued.Add(-int64(cap(f.buf)))
			releaseTunnelFrame(f)
		default:
			return
		}
	}
}
