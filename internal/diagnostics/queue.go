package diagnostics

import (
	"net"
	"time"
)

// Queue is a queue of writes in front of a socket: the frames of a tunnel
// waiting for its stream. QueueState must not wait - it reads what the
// writer keeps in atomics - and must stay safe to call after the writer has
// ended: a sample that races the stop calls it once more and drops what it
// read.
type Queue interface {
	QueueState() QueueState
}

// QueueState is a queue at one sample. The drops count from the start of the
// writer, so the difference of two samples is what was dropped between them.
type QueueState struct {
	// Frames wait in the queue now, in buffers of Bytes in all: what the
	// queue is bounded by, not their payload.
	Frames int
	Bytes  int64
	// DroppedFull were dropped because the queue was full, DroppedAge
	// because they waited in it too long.
	DroppedFull, DroppedAge uint64
	// WaitMax is the longest a frame written since the sample before waited
	// in the queue.
	WaitMax time.Duration
	// Writing says a write to the socket is in progress, for WriteElapsed so
	// far.
	Writing      bool
	WriteElapsed time.Duration
}

// watchedQueue is the queue of a sampled socket. A pointer of its own tells
// one watch from another of the same queue.
type watchedQueue struct{ Queue }

// ObserveQueue has the recorder sample q, the queue in front of c's socket,
// every sampleInterval right after the socket itself, when c is a socket it
// selected. It returns what ends that, nil when the recorder does not sample
// q; the end of the socket's sampling ends it too. A related socket, or one
// whose queue is watched already, takes none. A queue takes no slot and no
// token and starts no incident. Off, it costs one atomic load.
func ObserveQueue(c net.Conn, q Queue) (stop func()) {
	if current.Load() == nil {
		return nil
	}
	return observeQueue(c, q)
}

// observeQueue is ObserveQueue past its check.
func observeQueue(c net.Conn, q Queue) func() {
	r := current.Load()
	if r == nil || r.stopped.Load() {
		return nil
	}
	s := socketUnder(c)
	if s == nil {
		return nil
	}
	w := &watchedQueue{q}
	r.mu.Lock()
	_, sampled := r.sockets[s]
	ok := sampled && s.outer == nil && s.queue == nil
	if ok {
		s.queue = w
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return func() { r.unwatch(s, w) }
}

// unwatch ends the watch w of s's queue, unless it has ended already.
func (r *recorder) unwatch(s *socket, w *watchedQueue) {
	r.mu.Lock()
	if s.queue == w {
		s.queue = nil
	}
	r.mu.Unlock()
}

// sampleQueue records the queue w in front of s. Its state is read outside
// the lock and dropped if the watch ended meanwhile.
func (r *recorder) sampleQueue(s *socket, w *watchedQueue) {
	st := w.QueueState()
	r.mu.Lock()
	if s.queue == w {
		r.pushLocked(record{flow: s.flow, kind: kindQueue, payload: &st})
	}
	r.mu.Unlock()
}
