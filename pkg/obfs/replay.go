package obfs

import (
	"sync"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// SaltHistory records only authenticated first frames. Entries cover the
// entire accepted epoch interval and are never evicted for a new connection.
// At capacity, new sessions fail closed until an entry expires. Listeners
// using the same keys must share one history.
type SaltHistory struct {
	mu          sync.Mutex
	limit       int
	retention   time.Duration
	seen        map[[saltPrefix]byte]struct{}
	order       []saltEntry
	head, count int
}

type saltEntry struct {
	key     [saltPrefix]byte
	expires time.Time
}

const saltPrefix = 16

// DefaultSaltHistory bounds authenticated sessions retained concurrently.
const DefaultSaltHistory = 100000

// DefaultSaltRetention covers all epochs accepted by default Clocked,
// including the maximum future clock skew at the first acceptance.
const DefaultSaltRetention = time.Duration(2*veil.DefaultEpochWindow+1) * veil.EpochSeconds * time.Second

// NewSaltHistory creates a bounded history for default Clocked. Zero or less
// disables it. Size is capacity, not an eviction count.
func NewSaltHistory(size int) *SaltHistory {
	return NewSaltHistoryWithRetention(size, DefaultSaltRetention)
}

// NewSaltHistoryWithRetention supports other epoch windows. Retention must
// cover the scheme's entire replay interval. Zero retains entries for the
// process lifetime, for schemes without expiry; negative is treated as zero.
func NewSaltHistoryWithRetention(size int, retention time.Duration) *SaltHistory {
	if size <= 0 {
		return nil
	}
	return &SaltHistory{limit: size, retention: max(retention, 0),
		seen: make(map[[saltPrefix]byte]struct{}, size), order: make([]saltEntry, size)}
}

// Accept atomically checks and records an authenticated salt. Callers must
// verify the first frame before claiming capacity. False means a duplicate,
// a short salt, or exhausted capacity.
func (h *SaltHistory) Accept(salt []byte) bool { return h.record(salt) == "" }

func (h *SaltHistory) record(salt []byte) FailureReason {
	if h == nil {
		return ""
	}
	if len(salt) < saltPrefix {
		return ReasonShortFrame
	}
	var key [saltPrefix]byte
	copy(key[:], salt)
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.prune(now)
	if _, exists := h.seen[key]; exists {
		return ReasonReplay
	}
	if h.count == h.limit {
		return ReasonHistoryFull
	}
	entry := saltEntry{key: key}
	if h.retention > 0 {
		entry.expires = now.Add(h.retention)
	}
	h.order[(h.head+h.count)%h.limit] = entry
	h.seen[key] = struct{}{}
	h.count++
	return ""
}

func (h *SaltHistory) prune(now time.Time) {
	if h.retention == 0 {
		return
	}
	for h.count > 0 && !now.Before(h.order[h.head].expires) {
		delete(h.seen, h.order[h.head].key)
		h.order[h.head] = saltEntry{}
		h.head = (h.head + 1) % h.limit
		h.count--
	}
}

// Len reports live entries without exposing their contents.
func (h *SaltHistory) Len() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune(time.Now())
	return h.count
}
