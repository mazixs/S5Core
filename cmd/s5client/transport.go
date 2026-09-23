package main

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// Plan task Ф5-7: a client in the field changes its transport profile
// without anyone replacing its binary.
//
// Three things decide what the next connection looks like. TRANSPORT pins a
// transport or leaves the choice to the client (auto). The server's advice,
// carried inside every established tunnel and authenticated by the session
// keys, names the transport and shape it would rather see; an auto client
// follows it from its next connection. And a transport that has just failed
// to set up is rested for TRANSPORT_COOLDOWN while the other configured one
// takes its turn, so that a blocked port does not take the client down with
// it. The wire format is not a choice any more: the previous one was
// removed in 2.2, and OBFS_FORMAT only refuses to start on it
// (docs/field/migration.md, 4.1).
//
// Everything here is decided before the dial; nothing changes under a
// connection that is already up.

// transportKind is which transport a connection uses.
type transportKind string

const (
	transportAuto transportKind = "auto"
	transportObfs transportKind = "obfs"
	transportWS   transportKind = "ws"
)

// clientPolicy is the state shared by every connection of one client: the
// server's latest advice and which transports are resting. It is written
// from connection goroutines and read before every dial, hence the mutex;
// the work under it is a few comparisons.
type clientPolicy struct {
	mu  sync.Mutex
	now func() time.Time

	// pinned is TRANSPORT when it is not auto. A pinned transport is used
	// whatever the server advises and whatever has failed.
	pinned transportKind
	// wsConfigured says whether WS_URL is set: an advice to use ws is
	// only followable when the client knows where ws is.
	wsConfigured bool
	cooldown     time.Duration
	failedAt     map[transportKind]time.Time
	// advice is the latest one the server sent, already validated.
	advice *obfs.Advice
	// adviceNoWS remembers that the "ws advised without WS_URL" warning
	// has been given for the current advice, so it is given once.
	adviceNoWS bool
}

// newClientPolicy reads the policy settings out of the configuration and
// refuses the combinations that could not work: a transport the client has
// no address for, a value that is not a transport or a format at all.
func newClientPolicy(cfg clientParams) (*clientPolicy, error) {
	p := &clientPolicy{
		now:          time.Now,
		wsConfigured: cfg.WSUrl != "",
		cooldown:     cfg.TransportCooldown,
		failedAt:     map[transportKind]time.Time{},
	}

	switch transportKind(cfg.Transport) {
	case transportAuto, "":
	case transportObfs:
		p.pinned = transportObfs
	case transportWS:
		if !p.wsConfigured {
			return nil, fmt.Errorf("TRANSPORT=ws needs WS_URL: the client has no address to reach the WebSocket transport at")
		}
		p.pinned = transportWS
	default:
		return nil, fmt.Errorf("TRANSPORT %q is not one this build knows (auto, obfs, ws)", cfg.Transport)
	}

	if err := checkFormat(cfg.Format); err != nil {
		return nil, err
	}
	if p.cooldown < 0 {
		return nil, fmt.Errorf("TRANSPORT_COOLDOWN must not be negative")
	}
	return p, nil
}

// checkFormat accepts the names of the current wire format. legacy gets its
// own refusal: a client that silently spoke v1 instead would look to its
// operator like a server that stopped answering.
func checkFormat(format string) error {
	switch format {
	case "", "auto", "v1":
		return nil
	case "legacy":
		return fmt.Errorf("OBFS_FORMAT=legacy was removed in 2.2 together with the previous wire format; " +
			"current servers do not accept it. Remove OBFS_FORMAT or set it to v1 (docs/field/migration.md, 4.1)")
	default:
		return fmt.Errorf("OBFS_FORMAT %q is not one this build knows (auto, v1)", format)
	}
}

// configured is the transport the client would use with no advice and no
// failures: ws when a WS_URL was given, obfs otherwise - the rule the
// client has always applied.
func (p *clientPolicy) configured() transportKind {
	if p.wsConfigured {
		return transportWS
	}
	return transportObfs
}

// available says whether the client could dial the transport at all. obfs
// needs only SERVER_ADDR, which is required; ws needs WS_URL.
func (p *clientPolicy) available(t transportKind) bool {
	switch t {
	case transportObfs:
		return true
	case transportWS:
		return p.wsConfigured
	}
	return false
}

func (p *clientPolicy) coolingDown(t transportKind, now time.Time) bool {
	failed, ok := p.failedAt[t]
	return ok && p.cooldown > 0 && now.Sub(failed) < p.cooldown
}

// checkPrologue keeps the client on the printable opening. raw is refused
// rather than sent: on a filtering path it does not connect at all, and every
// 2.x server reads the printable one. The server still reads raw, for 2.0 and
// 2.1 clients configured with it.
func checkPrologue(v string) error {
	switch obfs.PrologueEncoding(v) {
	case "", obfs.ProloguePrintable:
		return nil
	case obfs.PrologueRaw:
		return fmt.Errorf("OBFS_PROLOGUE=raw was removed from the client in 2.2: every 2.x server reads the " +
			"printable opening, and the raw one is what a filtering path blocks. Remove OBFS_PROLOGUE or set it to printable")
	}
	return fmt.Errorf("OBFS_PROLOGUE %q is not one this build knows (printable)", v)
}

// chooseTransport is the whole decision, in order: a pinned transport; else
// the advised transport when the client can reach it, else the configured
// one; and if that one is resting after a failure, the other configured
// transport gets its turn. When everything is resting the preferred one is
// tried anyway - resting is a tie-breaker, not a refusal to connect.
func (p *clientPolicy) chooseTransport(now time.Time) transportKind {
	if p.pinned != "" {
		return p.pinned
	}
	preferred := p.configured()
	if p.advice != nil && p.advice.Transport != "" {
		if advised := transportKind(p.advice.Transport); p.available(advised) {
			preferred = advised
		}
	}
	if !p.coolingDown(preferred, now) {
		return preferred
	}
	for _, alt := range []transportKind{transportWS, transportObfs} {
		if alt != preferred && p.available(alt) && !p.coolingDown(alt, now) {
			return alt
		}
	}
	return preferred
}

// apply returns the configuration one connection attempt is made with: the
// transport chosen now, and the shape the server advised laid
// over the configured one. Fields the advice leaves at zero keep their
// configured values, so a server that only names a transport changes
// nothing else.
func (p *clientPolicy) apply(cfg clientParams) clientParams {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()

	cfg.transport = p.chooseTransport(now)

	if a := p.advice; a != nil {
		if a.WSMinFrame > 0 && a.WSMaxFrame > 0 {
			cfg.WSMinFrame, cfg.WSMaxFrame = a.WSMinFrame, a.WSMaxFrame
		}
		if a.WSMaxJitterMs > 0 {
			cfg.WSMaxJitterMs = a.WSMaxJitterMs
		}
		if a.MaxPadding > 0 {
			cfg.MaxPadding = a.MaxPadding
		}
		if a.KeepaliveMin > 0 && a.KeepaliveMax > 0 {
			cfg.KeepaliveMin, cfg.KeepaliveMax = a.KeepaliveMin, a.KeepaliveMax
		}
	}
	return cfg
}

// checkAdvice is the client's own view of what a usable advice is. The
// server validated its setting before sending it, but the client does not
// have to trust that: a shape that cannot work is dropped here, whole,
// rather than half-applied.
func checkAdvice(a obfs.Advice) error {
	switch transportKind(a.Transport) {
	case "", transportObfs, transportWS:
	default:
		return fmt.Errorf("transport %q is not one this build knows", a.Transport)
	}
	if (a.WSMinFrame > 0) != (a.WSMaxFrame > 0) {
		return fmt.Errorf("min_frame and max_frame must come together")
	}
	if a.WSMinFrame > a.WSMaxFrame {
		return fmt.Errorf("min_frame %d exceeds max_frame %d", a.WSMinFrame, a.WSMaxFrame)
	}
	if (a.KeepaliveMin > 0) != (a.KeepaliveMax > 0) {
		return fmt.Errorf("keepalive bounds must come together")
	}
	if a.KeepaliveMin > a.KeepaliveMax {
		return fmt.Errorf("keepalive %s-%s: the top is below the bottom", a.KeepaliveMin, a.KeepaliveMax)
	}
	if a.KeepaliveMax > time.Hour {
		return fmt.Errorf("keepalive up to %s would not keep anything alive", a.KeepaliveMax)
	}
	if a.MaxPadding > 4096 {
		return fmt.Errorf("padding %d is more than any frame carries", a.MaxPadding)
	}
	if a.WSMaxJitterMs > 60_000 {
		return fmt.Errorf("jitter of %d ms is a stall, not a jitter", a.WSMaxJitterMs)
	}
	return nil
}

// onAdvice is what the obfuscation layer calls when the server's advice
// arrives. It applies to the connections that come after this one; the one
// that carried it is left alone.
func (p *clientPolicy) onAdvice(a obfs.Advice) {
	if err := checkAdvice(a); err != nil {
		slog.Warn("The server's transport advice is not usable and was ignored", "error", err, "advice", a)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	changed := p.advice == nil || *p.advice != a
	p.advice = &a
	if changed {
		p.adviceNoWS = false
		attrs := []any{"transport", a.Transport, "padding", a.MaxPadding,
			"ws_frames", fmt.Sprintf("%d-%d", a.WSMinFrame, a.WSMaxFrame), "ws_jitter_ms", a.WSMaxJitterMs,
			"keepalive", fmt.Sprintf("%s-%s", a.KeepaliveMin, a.KeepaliveMax)}
		switch {
		case p.pinned != "" && a.Transport != "" && transportKind(a.Transport) != p.pinned:
			slog.Info("The server advises another transport; TRANSPORT is pinned, so only the shape is followed",
				append(attrs, "pinned", p.pinned)...)
		default:
			slog.Info("Transport advice received from the server; it applies from the next connection", attrs...)
		}
	}
	if transportKind(a.Transport) == transportWS && !p.wsConfigured && !p.adviceNoWS {
		p.adviceNoWS = true
		slog.Warn("The server advises the WebSocket transport but WS_URL is not set; staying on obfs. " +
			"Set WS_URL so that the client can move when asked to")
	}
}

// onFailure records a setup failure against the transport the attempt used.
// Only the phases that mean "this transport does not get through" count: a dial that never connected, or a server that
// accepted the connection and did not answer the greeting or the
// authentication. A CONNECT that fails is the destination's problem and
// says nothing about the path.
//
// phaseAuthRejected is deliberately not in that list. A rejection is an
// answer, and an answer proves the transport worked all the way through a
// SOCKS5 exchange; treating it as a path failure rested a working transport
// over a typo in the password (and, before 2.2, moved the client onto a wire
// format the server no longer accepted).
func (p *clientPolicy) onFailure(attempt clientParams, phase tunnelPhase) {
	switch phase {
	case phaseDial, phaseGreeting, phaseAuth:
	default:
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()

	if p.cooldown > 0 && p.pinned == "" {
		p.failedAt[attempt.transport] = now
		if other := p.otherAvailable(attempt.transport); other != "" && !p.coolingDown(other, now) {
			slog.Warn("Transport failed to set up; the next connection tries the other one",
				"failed", attempt.transport, "next", other, "phase", phase, "cooldown", p.cooldown)
		}
	}
}

// onSuccess clears the record of the transport that just worked.
func (p *clientPolicy) onSuccess(attempt clientParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.failedAt, attempt.transport)
}

func (p *clientPolicy) otherAvailable(t transportKind) transportKind {
	for _, alt := range []transportKind{transportWS, transportObfs} {
		if alt != t && p.available(alt) {
			return alt
		}
	}
	return ""
}

// describe is the startup line's summary of the policy.
func (p *clientPolicy) describe() []any {
	transport := string(transportAuto)
	if p.pinned != "" {
		transport = string(p.pinned)
	}
	return []any{"transport", transport, "default_transport", p.configured()}
}

// usesWS says whether this connection attempt goes over the WebSocket
// transport: what the policy chose when there is one, the old WS_URL rule
// when there is not - so a configuration built by hand, as the tests do,
// behaves as it always has.
func (cfg clientParams) usesWS() bool {
	if cfg.transport != "" {
		return cfg.transport == transportWS
	}
	return cfg.WSUrl != ""
}

// effectiveTransport names the transport for the hello and the logs.
func (cfg clientParams) effectiveTransport() transportKind {
	if cfg.usesWS() {
		return transportWS
	}
	return transportObfs
}

// dialTunnel is dialObfsTunnel under the policy: the attempt is shaped
// first, and its outcome is fed back so that the next attempt can differ.
// The attempt's configuration is returned so that the caller logs what was
// actually used, not what was configured. Without a policy - tests build
// their configuration by hand - it is dialObfsTunnel and nothing else.
func dialTunnel(cfg clientParams, connectReq []byte) (net.Conn, clientParams, error) {
	if cfg.policy == nil {
		conn, err := dialObfsTunnel(cfg, connectReq)
		return conn, cfg, err
	}
	attempt := cfg.policy.apply(cfg)
	conn, err := dialObfsTunnel(attempt, connectReq)
	if err != nil {
		cfg.policy.onFailure(attempt, tunnelPhaseOf(err))
		return nil, attempt, err
	}
	cfg.policy.onSuccess(attempt)
	return conn, attempt, nil
}
