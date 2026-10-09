package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// earlyDataFor is how long a node's announcement of early data is trusted
// without being heard again. Every tunnel through the node repeats it.
const earlyDataFor = 10 * time.Minute

// earlyData remembers wss nodes that announced obfs.CapWSEarlyData, by
// nativeKey. A node is dialled with early data only after it said so: an
// ordinary WebSocket server closes a connection with bytes behind the
// upgrade request, so the first connection to a node goes the old way.
var earlyData sync.Map // string -> time.Time

// earlyDistrustMax caps the distrust of a node that failed early data more
// than once: what fails twice is a front that will not heal by itself, and a
// day still notices one that was fixed, without a restart of the client.
const earlyDistrustMax = 24 * time.Hour

// earlyFailed remembers, by the same key, when early data last failed on a
// node and for how long its bit is not believed after that: one WS_URL in
// front of several nodes, or a front that loses early frames, would
// otherwise have every advice set it again for the next failure. The first
// failure costs earlyDataFor, every later one twice the previous window, up
// to earlyDistrustMax. Failures inside a window are one failure: the
// connections dialled together all fail together.
var earlyFailed = struct {
	sync.Mutex
	m map[string]earlyFailure
}{m: map[string]earlyFailure{}}

type earlyFailure struct {
	at     time.Time
	window time.Duration
}

// phaseEarlyUpgrade is an early dial that failed before the server's first
// byte otherwise than by a dial timeout: a refused upgrade, or a 101 and then
// silence. It says nothing against the transport - a node rolled back, set
// WS_EARLY_DATA=off or behind a front that loses early frames still takes
// the ordinary upgrade - so the policy does not count it and no hint about
// the PSK is given.
const phaseEarlyUpgrade tunnelPhase = "early_upgrade"

// adviceFor is the advice callback of one tunnel. Capabilities describe the
// listener the tunnel came through, so they are kept here and taken out
// before the policy compares advice: tunnels through two listeners of one
// server would otherwise log a change of advice on every switch.
func adviceFor(cfg clientParams) func(obfs.Advice) {
	return func(a obfs.Advice) {
		if cfg.usesWS() {
			key := nativeKey(cfg)
			if a.Capabilities&obfs.CapWSEarlyData != 0 && !distrusted(key) {
				if _, known := earlyData.Swap(key, time.Now()); !known {
					slog.Debug("The WebSocket node accepts early data", "url", cfg.WSUrl)
				}
			} else {
				earlyData.Delete(key)
			}
		}
		a.Capabilities = 0
		if cfg.policy != nil {
			cfg.policy.onAdvice(a)
		}
	}
}

// waitingForUpgrade makes dialServer wait for the 101 even on a node that
// accepts early data: for a spare, which has nothing to hurry and is checked
// as an established connection (hungUp, takenSpare), and for a setup done
// again, which must not fail the same way twice.
func waitingForUpgrade(cfg clientParams) clientParams {
	cfg.awaitUpgrade = true
	return cfg
}

func earlyDataKnown(cfg clientParams) bool {
	return !cfg.awaitUpgrade && recently(&earlyData, nativeKey(cfg))
}

func recently(m *sync.Map, key string) bool {
	at, ok := m.Load(key)
	return ok && time.Since(at.(time.Time)) < earlyDataFor
}

func distrusted(key string) bool {
	earlyFailed.Lock()
	defer earlyFailed.Unlock()
	f, ok := earlyFailed.m[key]
	return ok && time.Since(f.at) < f.window
}

func forgetEarlyData(key string) {
	earlyData.Delete(key)
	earlyFailed.Lock()
	defer earlyFailed.Unlock()
	now := time.Now()
	f, ok := earlyFailed.m[key]
	switch {
	case !ok:
		f.window = earlyDataFor
	case now.Sub(f.at) < f.window:
		return
	default:
		f.window = min(2*f.window, earlyDistrustMax)
	}
	f.at = now
	earlyFailed.m[key] = f
}

// dialWSEarly is the wss branch of dialServer for a node that accepts early
// data. It returns once the upgrade request is written; the 101 is awaited
// by the first read, which the greeting does anyway.
func dialWSEarly(ctx context.Context, cfg clientParams) (net.Conn, error) {
	shape := ws.Shape{MinFrame: cfg.WSMinFrame, MaxFrame: cfg.WSMaxFrame, MaxJitter: time.Duration(cfg.WSMaxJitterMs) * time.Millisecond}
	var conn *ws.EarlyConn
	var err error
	if cfg.wsDialer != nil {
		conn, err = cfg.wsDialer.DialEarly(ctx, shape)
	} else {
		conn, err = ws.DialEarly(ctx, cfg.wsOptions(), shape)
	}
	t := &earlyTunnel{EarlyConn: conn, key: nativeKey(cfg)}
	if err != nil {
		// An answer that came before the dial returned is the one the first
		// read would have seen.
		var ue *ws.UpgradeError
		if errors.As(err, &ue) {
			err = t.check(err)
		}
		return nil, fmt.Errorf("failed to dial WS: %w", err)
	}
	return t, nil
}

func isEarly(c net.Conn) bool {
	_, ok := c.(*earlyTunnel)
	return ok
}

// earlyTunnel forgets the node when anything fails before the server's
// first byte: a refused upgrade, and equally a front that answered 101 and
// lost the frames, which shows up only as a silent server. Such an error is
// returned as an *earlyUnanswered, which earlyPhaseOf classifies. Its own
// Close is not a failure of the node.
type earlyTunnel struct {
	*ws.EarlyConn
	key      string
	answered atomic.Bool
	forget   sync.Once
}

func (t *earlyTunnel) Read(b []byte) (int, error) {
	n, err := t.EarlyConn.Read(b)
	if n > 0 {
		t.answered.Store(true)
	}
	return n, t.check(err)
}

func (t *earlyTunnel) Write(b []byte) (int, error) {
	n, err := t.EarlyConn.Write(b)
	return n, t.check(err)
}

func (t *earlyTunnel) SetDeadline(d time.Time) error {
	return t.check(t.EarlyConn.SetDeadline(d))
}

func (t *earlyTunnel) check(err error) error {
	if err == nil || t.answered.Load() || errors.Is(err, net.ErrClosed) {
		return err
	}
	t.forget.Do(func() { forgetEarlyData(t.key) })
	return &earlyUnanswered{err: err, upgraded: t.EarlyConn != nil && t.Upgraded()}
}

// earlyUnanswered is a failure of an early tunnel before the server's first
// byte; upgraded says whether the 101 had come by then.
type earlyUnanswered struct {
	err      error
	upgraded bool
}

func (e *earlyUnanswered) Error() string { return e.err.Error() }
func (e *earlyUnanswered) Unwrap() error { return e.err }

// earlyRefused says an early upgrade was answered with an HTTP status other
// than 101: nothing upgraded, so the server saw none of the request, and the
// setup may be repeated (markRetry). A front passes bytes behind a request
// on only after the 101. An upgrade cut or timed out without an answer is not
// a refusal: the request may have reached the server. Nor is a 101 the client
// rejected (a bad Sec-WebSocket-Accept, a 101 at the end of the dial budget):
// the path switched, and the early frames may have gone on.
func earlyRefused(err error) bool {
	var ue *ws.UpgradeError
	return errors.As(err, &ue) && ue.Status != 0 && ue.Status != http.StatusSwitchingProtocols
}

// earlyPhaseOf is the one classification of an early tunnel that failed
// before the server's first byte. A timeout before the 101, by whichever
// deadline it came, is the dial's, as it was before early data. Everything
// else - a refusal, or a 101 and then silence until the greeting's deadline -
// is phaseEarlyUpgrade.
func earlyPhaseOf(err error) (tunnelPhase, bool) {
	var e *earlyUnanswered
	if !errors.As(err, &e) {
		return "", false
	}
	if !e.upgraded && isTimeout(err) {
		return phaseDial, true
	}
	return phaseEarlyUpgrade, true
}
