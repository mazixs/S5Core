package obfs

import "sync"

// SaltHistory remembers the session salts a server has already accepted, so
// that a recorded connection cannot be replayed into a new one.
//
// It replaces a per-connection nonce window. That window cost about 82 KiB per
// connection and could only catch a frame repeated inside the same session -
// which counter nonces now make impossible anyway. The case it never covered
// is the one an active prober actually uses: record the first frame of a
// working connection and send it again on a fresh socket. The salt is what
// makes that frame decrypt, so the salt is what has to be remembered, and it
// has to be remembered across connections. That is a server-wide structure,
// not a per-connection one: one history of 10 000 entries costs a few hundred
// kilobytes for the whole process.
//
// The history is exact, not probabilistic. A Bloom filter would be smaller and
// would occasionally drop a legitimate connection, which is a worse failure
// than the memory it saves.
type SaltHistory struct {
	mu    sync.Mutex
	limit int
	seen  map[[saltPrefix]byte]struct{}
	order [][saltPrefix]byte
	pos   int
}

// saltPrefix is how much of a salt is stored. 16 bytes make an accidental
// collision - which would close a legitimate connection - about as likely as
// guessing an AES key, while halving what the history costs.
const saltPrefix = 16

// DefaultSaltHistory is the number of salts a history remembers when the
// caller does not say. It is the window an active prober has to beat: a replay
// works only if the server has forgotten the original, which takes this many
// connections since it was made.
const DefaultSaltHistory = 10000

// NewSaltHistory creates a history of the given size. A size of zero or less
// gives a history that accepts everything, which is what a caller that does
// not want the check should pass.
func NewSaltHistory(size int) *SaltHistory {
	if size <= 0 {
		return nil
	}
	return &SaltHistory{
		limit: size,
		seen:  make(map[[saltPrefix]byte]struct{}, size),
		order: make([][saltPrefix]byte, 0, size),
	}
}

// Accept reports whether this salt is new, and records it. A false answer
// means the exact bytes have been seen before within the history's window.
//
// It is safe for concurrent use: one history serves every connection a
// listener accepts.
func (h *SaltHistory) Accept(salt []byte) bool {
	if h == nil {
		return true
	}
	if len(salt) < saltPrefix {
		return false
	}

	var key [saltPrefix]byte
	copy(key[:], salt)

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.seen[key]; exists {
		return false
	}
	h.seen[key] = struct{}{}

	if len(h.order) < h.limit {
		h.order = append(h.order, key)
		return true
	}

	// Full: the oldest entry makes room for this one.
	delete(h.seen, h.order[h.pos])
	h.order[h.pos] = key
	h.pos = (h.pos + 1) % h.limit
	return true
}

// Len reports how many salts the history currently holds.
func (h *SaltHistory) Len() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.seen)
}
