package userstore

import "time"

// Test helpers. Production asks SessionStatus and counts through
// TrafficCounterFor.

// SessionAllowed is the boolean view of SessionStatus.
func (s *Store) SessionAllowed(username string) bool {
	return s.SessionStatus(username) == SessionAllowed
}

// AddTraffic adds to the unflushed counter, as the relay does.
func (s *Store) AddTraffic(username string, bytes int64) {
	s.mu.RLock()
	entry, ok := s.users[username]
	s.mu.RUnlock()

	if ok {
		entry.trafficDelta.Add(bytes)
	}
}

func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// verify is verifyResult for a KDF stand-in that cannot fail.
func (c *verifierCache) verify(username, password, hash string, now time.Time, slow func() bool) (ok bool, path VerifyPath) {
	ok, path, _ = c.verifyResult(username, password, hash, now, func() (bool, error) { return slow(), nil })
	return ok, path
}

func (c *verifierCache) size() int {
	if c == nil || c.items == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
