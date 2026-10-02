package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// udpReportEvery is how often a live association reports what it has
// carried. The line that closes it is written once, at its end, and a client
// that is killed never writes it: the Windows full tunnel stops the client
// that way, and the associations alive at that moment are the long ones - a
// match, a call - that the log is taken for (docs/plan/draft.md, Ч-9).
const udpReportEvery = time.Minute

// quietFloor is how many datagrams the busier direction needs before the
// other can count as quiet. Below it an association is a lookup or a probe.
const quietFloor = 100

// Who ended an association. The application closing its SOCKS5 connection is
// how an association is meant to end; the tunnel or the client's own socket
// failing is not.
const (
	endApplication = "application"
	endTunnel      = "tunnel"
	endLocal       = "local"
)

type assocEnd struct {
	by  string
	err error
}

// assocStats counts the datagrams of one association both ways, as the
// application sent and received them.
type assocStats struct {
	sent, sentBytes, received, receivedBytes atomic.Uint64
}

func (s *assocStats) addSent(n int) {
	s.sent.Add(1)
	s.sentBytes.Add(uint64(n))
}

func (s *assocStats) addReceived(n int) {
	s.received.Add(1)
	s.receivedBytes.Add(uint64(n))
}

type assocTotals struct {
	sent, sentBytes, received, receivedBytes uint64
}

func (s *assocStats) totals() assocTotals {
	return assocTotals{s.sent.Load(), s.sentBytes.Load(), s.received.Load(), s.receivedBytes.Load()}
}

func (t assocTotals) minus(o assocTotals) assocTotals {
	return assocTotals{t.sent - o.sent, t.sentBytes - o.sentBytes, t.received - o.received, t.receivedBytes - o.receivedBytes}
}

func (t assocTotals) attrs() []any {
	return []any{"sent", t.sent, "sent_bytes", t.sentBytes, "received", t.received, "received_bytes", t.receivedBytes}
}

// quiet names the direction that carried less than a hundredth of the
// other, once the other has carried quietFloor datagrams. A game association
// re-created in the middle of a match carried 2.4 KB up against 12 MB down
// for three minutes and closed like any other, and nothing in the log said
// that its upstream had all but stopped (docs/plan/draft.md, Ч-4).
func (t assocTotals) quiet() string {
	switch {
	case t.received >= quietFloor && t.sent*100 < t.received:
		return "sent"
	case t.sent >= quietFloor && t.received*100 < t.sent:
		return "received"
	}
	return ""
}

// assocReport writes the line of a live association every udpReportEvery
// with its totals so far, and nothing for a period that carried nothing, so
// that a killed client loses at most the last period of each.
type assocReport struct {
	stats  *assocStats
	opened time.Time
	extra  func() []any

	mu      sync.Mutex
	last    assocTotals
	timer   *time.Timer
	stopped bool
}

func startAssocReport(stats *assocStats, opened time.Time, extra func() []any) *assocReport {
	r := &assocReport{stats: stats, opened: opened, extra: extra}
	r.mu.Lock()
	r.timer = time.AfterFunc(udpReportEvery, r.tick)
	r.mu.Unlock()
	return r
}

func (r *assocReport) tick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	if now := r.stats.totals(); now != r.last {
		attrs := append([]any{"age", time.Since(r.opened).Round(time.Second).String()}, now.attrs()...)
		// Quiet in this period, not since the start: an upstream that stops
		// in the tenth minute of a match is buried in nine good ones.
		if q := now.minus(r.last).quiet(); q != "" {
			attrs = append(attrs, "quiet", q)
		}
		if r.extra != nil {
			attrs = append(attrs, r.extra()...)
		}
		slog.Info("UDP Tunnel running", attrs...)
		r.last = now
	}
	r.timer.Reset(udpReportEvery)
}

// stop ends the reports. A line already being written is finished first, so
// none follows the line that closes the association.
func (r *assocReport) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	r.timer.Stop()
}

// logAssocClosed writes the line that ends an association, at Warn when it
// did not end the way an association should or a direction was quiet: a
// client that logs at Warn, as the full tunnel did, showed nothing of either.
func logAssocClosed(end assocEnd, opened time.Time, t assocTotals, extra []any) {
	level := slog.LevelInfo
	if end.by != endApplication {
		level = slog.LevelWarn
	}
	attrs := append([]any{"closed_by", end.by, "reason", end.err, "age", time.Since(opened).Round(time.Second).String()}, t.attrs()...)
	if q := t.quiet(); q != "" {
		attrs = append(attrs, "quiet", q)
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, "UDP Tunnel closed", append(attrs, extra...)...)
}
