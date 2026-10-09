package main

import (
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
)

func lostFirstSizes() func(int) bool {
	count := 0
	return func(size int) bool {
		if size <= 200 {
			return false
		}
		count++
		return count <= 12
	}
}

func TestCorrelatedSizeLossRecoversBothEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startSized(t, 0, lostFirstSizes())
		l.at(time.Second)
		if l.client.session.Limit() >= nativeudp.FloorWire {
			t.Fatal("loss did not reproduce the undersized limit")
		}
		l.at(35 * time.Second)
		limit := l.client.session.Limit()
		if limit < nativeudp.MaxWire-8 || l.path.server.Limit() != limit {
			t.Fatalf("client %d, server %d", limit, l.path.server.Limit())
		}
		if l.client.carry(make([]byte, 1222)) != byNative {
			t.Fatal("IPv6 QUIC Initial is still dropped")
		}
		synctest.Wait()
		probes := l.client.stats.sizeProbes.Load()
		l.at(10 * time.Minute)
		if l.client.stats.sizeProbes.Load() != probes {
			t.Fatal("wide path keeps sending size probes")
		}
	})
}

func TestNarrowPathRecoveryHasAFiniteBudget(t *testing.T) {
	for _, path := range []int{1230, 1357} {
		t.Run(strconv.Itoa(path), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := startSized(t, path, nil)
				l.at(time.Second)
				initial := l.client.stats.sizeProbes.Load()
				l.at(3 * time.Minute)
				if l.client.session.Limit() > path || l.path.server.Limit() > path {
					t.Fatal("recovery exceeded the path")
				}
				probes := l.client.stats.sizeProbes.Load()
				if probes <= initial || probes > initial+3*42 {
					t.Fatalf("unbounded recovery: %d initial, %d final", initial, probes)
				}
				l.at(10 * time.Minute)
				if l.client.stats.sizeProbes.Load() != probes {
					t.Fatal("recovery budget did not stop the search")
				}
			})
		})
	}
}

func TestOldSizedServerDoesNotNegotiateRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lose := lostFirstSizes()
		l := startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) { p.sizes = true; p.legacyLimits = true; p.loseSized = lose })
		l.at(time.Second)
		limit, probes := l.client.session.Limit(), l.client.stats.sizeProbes.Load()
		l.at(10 * time.Minute)
		if l.client.recoverySupported.Load() || l.client.session.Limit() != limit || l.client.stats.sizeProbes.Load() != probes {
			t.Fatal("legacy server was sent a recovery search")
		}
	})
}

func TestLostAndMismatchedLimitAcknowledgementsCannotRaiseTheClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lose := lostFirstSizes()
		l := startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) {
			p.sizes = true
			p.loseSized = lose
			p.loseLimitACK = func(p nativeudp.Probe) bool { return p.Generation > 1 && p.Limit != 0 }
		})
		l.at(time.Second)
		old := l.client.session.Limit()
		l.at(31 * time.Second)
		generation, limit := l.path.server.NegotiatedLimit()
		if generation != 2 || limit < nativeudp.MaxWire-8 || l.client.session.Limit() != old {
			t.Fatalf("unacknowledged proposal: gen %d, limit %d, client %d", generation, limit, l.client.session.Limit())
		}
		for _, a := range []nativeudp.Answer{{Generation: 1, Limit: limit}, {Generation: generation, Limit: old}, {Generation: 3, Limit: limit}} {
			l.client.limitACK <- a
			synctest.Wait()
			if l.client.session.Limit() != old {
				t.Fatal("wrong generation or value committed")
			}
		}
		l.client.limitACK <- nativeudp.Answer{Generation: generation, Limit: limit}
		synctest.Wait()
		if l.client.session.Limit() != limit {
			t.Fatal("exact acknowledgement not committed")
		}
		l.client.limitACK <- nativeudp.Answer{Generation: 1, Limit: old}
		synctest.Wait()
		if l.client.session.Limit() != limit {
			t.Fatal("delayed acknowledgement changed the limit")
		}
	})
}

func TestLostProposalAcknowledgementsExhaustTheRecoveryBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lose := lostFirstSizes()
		l := startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) {
			p.sizes = true
			p.loseSized = lose
			p.loseLimitACK = func(p nativeudp.Probe) bool { return p.Generation > 1 && p.Limit != 0 }
		})
		l.at(time.Second)
		old := l.client.session.Limit()
		l.at(45 * time.Second)
		if l.path.server.Limit() != old || l.client.session.Limit() != old {
			t.Fatal("endpoints did not converge after the announcement budget")
		}
		// Delayed acknowledgement of the cancelled proposal cannot commit it.
		l.client.limitACK <- nativeudp.Answer{Generation: 2, Limit: nativeudp.MaxWire - 6}
		synctest.Wait()
		l.at(5 * time.Minute)
		probes := l.client.stats.sizeProbes.Load()
		l.at(10 * time.Minute)
		if l.client.session.Limit() != old || l.client.stats.sizeProbes.Load() != probes {
			t.Fatal("lost acknowledgements raised the limit or kept searching")
		}
		if server := l.path.server.Limit(); server != old {
			t.Fatalf("lost limit acknowledgements left the endpoints divergent: client=%d server=%d", old, server)
		}
	})
}

func TestLostLimitCancellationIsRepeatedAtExistingProbeCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lostCancellations := 0
		l := startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) {
			p.sizes = true
			p.loseSized = lostFirstSizes()
			p.loseLimitACK = func(p nativeudp.Probe) bool { return p.Generation > 1 && p.Limit != 0 }
			p.loseLimitProposal = func(p nativeudp.Probe) bool {
				if p.Generation == 3 && p.Limit != 0 && lostCancellations < 2 {
					lostCancellations++
					return true
				}
				return false
			}
		})
		l.at(time.Second)
		old := l.client.session.Limit()
		l.at(80 * time.Second)
		if lostCancellations != 2 || l.path.server.Limit() != old || l.client.session.Limit() != old {
			t.Fatalf("lost cancellations=%d client=%d server=%d", lostCancellations, l.client.session.Limit(), l.path.server.Limit())
		}
		if count := l.path.probes.Load(); count > 30 {
			t.Fatalf("rollback increased the probe cadence: %d controls", count)
		}
	})
}
