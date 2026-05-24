package obfs



// replayWindow tracks recently seen nonces to detect replay attacks.
// It is designed for a single connection and is not safe for concurrent use
// (obfs conn has one reader goroutine).
type replayWindow struct {
	window int
	seen   map[[12]byte]struct{}
	order  [][12]byte
	pos    int
}

// newReplayWindow creates a new replay window with the given capacity.
// If capacity is <= 0, the returned window is a no-op.
func newReplayWindow(capacity int) *replayWindow {
	if capacity <= 0 {
		return nil
	}
	return &replayWindow{
		window: capacity,
		seen:   make(map[[12]byte]struct{}, capacity),
		order:  make([][12]byte, 0, capacity),
	}
}

// checkAndAdd returns true if the nonce is new and has been recorded.
// It returns false if the nonce was seen before (replay detected).
func (r *replayWindow) checkAndAdd(nonce []byte) bool {
	if r == nil {
		return true
	}

	if len(nonce) != 12 {
		return false
	}

	var n [12]byte
	copy(n[:], nonce)

	// Special case: the nonce being added is the oldest entry in the
	// full window and is about to be evicted. Renew its position.
	if len(r.order) == r.window && r.order[r.pos] == n {
		r.pos = (r.pos + 1) % r.window
		return true
	}

	if _, exists := r.seen[n]; exists {
		return false
	}

	r.seen[n] = struct{}{}

	if len(r.order) < r.window {
		r.order = append(r.order, n)
	} else {
		// Evict the oldest entry
		old := r.order[r.pos]
		delete(r.seen, old)
		r.order[r.pos] = n
		r.pos = (r.pos + 1) % r.window
	}

	return true
}

// reset clears the replay window.
func (r *replayWindow) reset() {
	if r == nil {
		return
	}
	for k := range r.seen {
		delete(r.seen, k)
	}
	r.order = r.order[:0]
	r.pos = 0
}

var _ = (*replayWindow)(nil) // ensure type is used
