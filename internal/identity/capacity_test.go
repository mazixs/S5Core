package identity

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func TestGuardCapsMapsWithoutEvictingActiveBans(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(staticCredentials{"alice": "right"}, Options{MaxRetries: 1, BanTime: time.Minute, Logger: discardLogger()})
		g.capacity = 2
		g.sleep = func(time.Duration) {}
		var keys []string
		shard := g.shardFor("source-0")
		for i := 0; len(keys) < 3; i++ {
			key := fmt.Sprintf("source-%d", i)
			if g.shardFor(key) == shard {
				keys = append(keys, key)
			}
		}
		for _, key := range keys[:2] {
			g.ValidFrom("missing", "bad", key)
		}
		if g.ValidFrom("alice", "right", keys[2]) {
			t.Fatal("full shard admitted a new source")
		}
		for _, key := range keys[:2] {
			if g.ValidFrom("alice", "right", key) {
				t.Fatal("capacity evicted a live ban")
			}
		}
		if len(shard.failures) != 2 || len(shard.banned) != 2 {
			t.Fatal("source maps exceeded capacity")
		}
		for i := range 10000 {
			g.recordAccountFailure(fmt.Sprintf("missing-%d", i), time.Now())
		}
		for i := range g.accounts {
			if len(g.accounts[i].failures) > 2 {
				t.Fatal("account map exceeded capacity")
			}
		}
		time.Sleep(time.Minute)
		if !g.ValidFrom("alice", "right", keys[2]) {
			t.Fatal("expired entries did not free capacity")
		}
	})
}
