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
// it. OBFS_FORMAT does the same for the wire format itself: auto tries the
// current format and falls back to the previous one when a server that
// accepted the connection does not answer, for OBFS_FORMAT_REPROBE.
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

// formatKind is which obfuscation format a connection speaks.
type formatKind string

const (
	formatAuto   formatKind = "auto"
	formatV1     formatKind = "v1"
	formatLegacy formatKind = "legacy"
)

// clientPolicy is the state shared by every connection of one client: the
// server's latest advice, which transports are resting, and whether the
// previous format is in use. It is written from connection goroutines and
// read before every dial, hence the mutex; the work under it is a few
// comparisons.
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

	// pinnedFormat is OBFS_FORMAT when it is not auto.
	pinnedFormat formatKind
	reprobe      time.Duration
	// legacyUntil, when in the future, sends connections over the
	// previous format; zero means the current one.
	legacyUntil time.Time
	// legacyWarned rate-limits the "you are on the old format" warning
	// to once per fallback window.
	legacyWarned bool
}

// newClientPolicy reads the policy settings out of the configuration and
// refuses the combinations that could not work: a transport the client has
// no address for, a value that is not a transport or a format at all.
func newClientPolicy(cfg clientParams) (*clientPolicy, error) {
	p := &clientPolicy{
		now:          time.Now,
		wsConfigured: cfg.WSUrl != "",
		cooldown:     cfg.TransportCooldown,
		reprobe:      cfg.FormatReprobe,
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

	switch formatKind(cfg.Format) {
	case formatAuto, "":
	case formatV1, formatLegacy:
		p.pinnedFormat = formatKind(cfg.Format)
	default:
		return nil, fmt.Errorf("OBFS_FORMAT %q is not one this build knows (auto, v1, legacy)", cfg.Format)
	}

	if p.cooldown < 0 || p.reprobe < 0 {
		return nil, fmt.Errorf("TRANSPORT_COOLDOWN and OBFS_FORMAT_REPROBE must not be negative")
	}
	return p, nil
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

func (p *clientPolicy) chooseFormat(now time.Time) formatKind {
	if p.pinnedFormat != "" {
		return p.pinnedFormat
	}
	if now.Before(p.legacyUntil) {
		return formatLegacy
	}
	return formatV1
}

// apply returns the configuration one connection attempt is made with: the
// transport and format chosen now, and the shape the server advised laid
// over the configured one. Fields the advice leaves at zero keep their
// configured values, so a server that only names a transport changes
// nothing else.
func (p *clientPolicy) apply(cfg clientParams) clientParams {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()

	cfg.transport = p.chooseTransport(now)
	cfg.format = p.chooseFormat(now)

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

// onFailure records a setup failure against the transport and format the
// attempt used. Only the phases that mean "this transport or format does
// not get through" count: a dial that never connected, or a server that
// accepted the connection and did not answer the greeting or the
// authentication. A CONNECT that fails is the destination's problem and
// says nothing about the path.
//
// phaseAuthRejected is deliberately not in that list. A rejection is an
// answer, and an answer proves the transport and the format worked all the
// way through a SOCKS5 exchange; treating it as a path failure made a wrong
// password move the whole client onto the previous wire format for the
// reprobe window - a format the server no longer accepts, so a typo took the
// client down for ten minutes and blamed the PSK in the log.
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

	// The dial did connect and nothing came back: that is what a server
	// on the other format looks like from here (and also what a wrong PSK
	// looks like, which the hint in the log says). Auto tries the other
	// format next, for a while; if that fails too, it comes back.
	if phase == phaseDial || p.pinnedFormat != "" || p.reprobe <= 0 {
		return
	}
	switch attempt.format {
	case formatV1:
		p.legacyUntil = now.Add(p.reprobe)
		p.legacyWarned = false
		slog.Warn("The server did not answer the current obfuscation format; the next connection tries the previous one",
			"phase", phase, "for", p.reprobe,
			"hint", "if the server is an older build, update it: the previous format is scheduled for removal (docs/field/migration.md)")
	case formatLegacy:
		p.legacyUntil = time.Time{}
	}
}

// onSuccess clears the record of the transport that just worked and, if the
// attempt spoke the current format, ends any fallback to the previous one.
func (p *clientPolicy) onSuccess(attempt clientParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.failedAt, attempt.transport)
	switch attempt.format {
	case formatV1:
		p.legacyUntil = time.Time{}
	case formatLegacy:
		if !p.legacyWarned {
			p.legacyWarned = true
			slog.Warn("Connected over the previous obfuscation format: the server is an older build. "+
				"Update the server - this format is scheduled for removal (docs/field/migration.md)",
				"pinned", p.pinnedFormat != "")
		}
	}
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
	format := string(formatAuto)
	if p.pinnedFormat != "" {
		format = string(p.pinnedFormat)
	}
	return []any{"transport", transport, "default_transport", p.configured(), "format", format}
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
