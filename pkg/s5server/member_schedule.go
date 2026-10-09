package s5server

import (
	"context"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// maintainMembers refreshes both epoch tables and membership at validity
// boundaries. File/SDK changes wake the timer after publishing their table.
// There is no account scan on packet delivery or tunnel authentication.
func (s *Server) maintainMembers(ctx context.Context) {
	if s.members == nil || s.userStore == nil {
		return
	}
	refresh := func() {
		if err := s.rebuildMembers(); err != nil {
			s.logger.Error("Tunnel member refresh failed", "error", err)
		}
	}
	refresh()
	for {
		now := time.Now()
		delay := time.Duration(veil.EpochSeconds) * time.Second / 4
		if next := s.userStore.NextTunnelValidityChange(now); !next.IsZero() {
			delay = min(delay, next.Sub(now))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.membersChanged:
			timer.Stop()
		case <-timer.C:
			refresh()
		}
	}
}
