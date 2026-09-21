package s5server

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Plan task Ф5-7: moving clients in the field without a release.
//
// The server has two things to do for that. It tells every client which
// transport and which traffic shape it would rather see - TRANSPORT_ADVICE,
// carried inside the tunnel as an advice frame - and it counts which builds
// arrive on which transport, so that the operator can see the migration
// happen instead of guessing at it. Both are here.

// ParseTransportAdvice turns the TRANSPORT_ADVICE setting into the frame the
// obfuscation layer sends. The syntax is a list of key=value pairs separated
// by spaces or commas; a bare word is the transport:
//
//	TRANSPORT_ADVICE="ws"
//	TRANSPORT_ADVICE="transport=ws min_frame=512 max_frame=2048 jitter_ms=5 padding=128 keepalive=10s-20s"
//
// Empty means no advice is sent. Every number is bounded here so that a typo
// on the server cannot hand a client a shape it will refuse or one that
// silently breaks its own tunnel.
func ParseTransportAdvice(raw string) (*obfs.Advice, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var a obfs.Advice
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
	for _, field := range fields {
		key, value, hasValue := strings.Cut(field, "=")
		if !hasValue {
			// A bare word is the transport, the one thing most operators
			// will ever set.
			if a.Transport != "" {
				return nil, fmt.Errorf("transport named twice: %q and %q", a.Transport, key)
			}
			if err := checkAdvisedTransport(key); err != nil {
				return nil, err
			}
			a.Transport = key
			continue
		}
		switch key {
		case "transport":
			if err := checkAdvisedTransport(value); err != nil {
				return nil, err
			}
			a.Transport = value
		case "min_frame":
			n, err := adviceNumber(key, value, 1, 65535)
			if err != nil {
				return nil, err
			}
			a.WSMinFrame = n
		case "max_frame":
			n, err := adviceNumber(key, value, 1, 65535)
			if err != nil {
				return nil, err
			}
			a.WSMaxFrame = n
		case "jitter_ms":
			n, err := adviceNumber(key, value, 1, 60_000)
			if err != nil {
				return nil, err
			}
			a.WSMaxJitterMs = n
		case "padding":
			// The same ceiling the server applies to its own OBFS_MAX_PADDING.
			n, err := adviceNumber(key, value, 1, 4096)
			if err != nil {
				return nil, err
			}
			a.MaxPadding = n
		case "keepalive":
			lo, hi, err := adviceRange(value)
			if err != nil {
				return nil, fmt.Errorf("keepalive: %w", err)
			}
			a.KeepaliveMin, a.KeepaliveMax = lo, hi
		default:
			return nil, fmt.Errorf("unknown field %q (known: transport, min_frame, max_frame, jitter_ms, padding, keepalive)", key)
		}
	}

	if a.WSMinFrame > 0 && a.WSMaxFrame > 0 && a.WSMinFrame > a.WSMaxFrame {
		return nil, fmt.Errorf("min_frame (%d) exceeds max_frame (%d)", a.WSMinFrame, a.WSMaxFrame)
	}
	if (a.WSMinFrame > 0) != (a.WSMaxFrame > 0) {
		// Half a band is not a band: the client applies the pair together.
		return nil, fmt.Errorf("min_frame and max_frame must be given together")
	}
	if a == (obfs.Advice{}) {
		return nil, fmt.Errorf("%q names nothing to advise", raw)
	}
	return &a, nil
}

func checkAdvisedTransport(name string) error {
	switch name {
	case TransportObfs, TransportWS:
		return nil
	}
	return fmt.Errorf("transport %q is not one a client can be sent to (obfs or ws)", name)
}

func adviceNumber(key, value string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", key, value)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%s: %d is outside %d..%d", key, n, lo, hi)
	}
	return n, nil
}

// adviceRange parses "10s-20s". Both ends are whole seconds, because that
// is what the frame carries; both are bounded well under the hour, because
// a keepalive that fires less often than any middlebox timeout is a
// keepalive that does nothing.
func adviceRange(value string) (time.Duration, time.Duration, error) {
	loRaw, hiRaw, ok := strings.Cut(value, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%q is not a range like 10s-20s", value)
	}
	lo, err := time.ParseDuration(loRaw)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a duration", loRaw)
	}
	hi, err := time.ParseDuration(hiRaw)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a duration", hiRaw)
	}
	const ceiling = 3600 * time.Second
	if lo < time.Second || hi < time.Second || lo > ceiling || hi > ceiling {
		return 0, 0, fmt.Errorf("%s-%s is outside 1s..1h", lo, hi)
	}
	if lo%time.Second != 0 || hi%time.Second != 0 {
		return 0, 0, fmt.Errorf("%s-%s: whole seconds only", lo, hi)
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("%s-%s: the top is below the bottom", lo, hi)
	}
	return lo, hi, nil
}

// validateAdvice checks TRANSPORT_ADVICE against the rest of the
// configuration: a transport the server does not listen on is not one it
// may send clients to.
func validateAdvice(cfg Config) error {
	a, err := ParseTransportAdvice(cfg.TransportAdvice)
	if err != nil {
		return fmt.Errorf("TRANSPORT_ADVICE is not usable: %w", err)
	}
	if a == nil {
		return nil
	}
	switch a.Transport {
	case TransportObfs:
		if !cfg.ObfsEnabled {
			return fmt.Errorf("TRANSPORT_ADVICE sends clients to obfs, but OBFS_ENABLED is false")
		}
	case TransportWS:
		if !cfg.WSEnabled {
			return fmt.Errorf("TRANSPORT_ADVICE sends clients to ws, but WS_ENABLED is false")
		}
	}
	return nil
}

// UpdateTransportAdvice replaces what the server recommends, from the next
// accepted connection onward - the same semantics as the other Update
// methods, and the way SIGHUP applies a changed TRANSPORT_ADVICE. The whole
// point of the setting is that changing it is cheap, and a restart is not
// cheap on a server with tunnels open.
func (s *Server) UpdateTransportAdvice(raw string) error {
	cfg := s.cfg
	cfg.TransportAdvice = raw
	if err := validateAdvice(cfg); err != nil {
		return err
	}
	a, _ := ParseTransportAdvice(raw)
	s.advice.Store(a)
	return nil
}

// currentAdvice is what a connection accepted now gets. Nil means nothing
// is sent.
func (s *Server) currentAdvice() *obfs.Advice {
	return s.advice.Load()
}

// clientHelloObserver builds the callback the obfuscation layer invokes when
// a client names itself. transport is the listener's label - what the client
// claims is logged, not counted, because the listener knows and the client
// only believes.
//
// The version goes into a label, and docs/design/observability-policy.md forbids a
// label whose value set is chosen by traffic. This one is chosen by traffic,
// so it is fenced twice: the string is cut down to what a build identifier
// is made of, and the set of distinct values the server will ever emit is
// capped by versions, after which every new build is "other". A peer needs
// the PSK to put anything here at all; the fence is for the day a peer with
// the PSK is not on our side.
func clientHelloObserver(t *Telemetry, logger *slog.Logger, transport string, versions *versionLabels) func(obfs.Hello) {
	return func(h obfs.Hello) {
		version := versions.label(h.Version)
		if t != nil && t.ClientConnections != nil {
			t.ClientConnections.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("client_version", version),
				attribute.String("transport", transport),
			))
		}
		if logger != nil {
			logger.Debug("Client introduced itself",
				"client_version", version,
				"transport", transport,
				"client_believes", h.Transport,
			)
		}
	}
}

// maxVersionLabels is how many distinct client builds one server names in
// its metrics; the rest are "other". A fleet mid-migration has two or three
// builds in it, a neglected one perhaps ten. Thirty-two is well above that
// and well below what would trouble Prometheus.
const maxVersionLabels = 32

// The two values that never take a slot.
const (
	versionUnknown = "unknown"
	versionOther   = "other"
)

// versionLabels is the fence on the client_version label: the first
// maxVersionLabels distinct builds are named, every later one is "other".
// Shared by every listener of a server, so the cap is per server, not per
// transport. The zero value is ready to use.
type versionLabels struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (v *versionLabels) label(version string) string {
	name := sanitizeVersion(version)
	if name == versionUnknown || name == versionOther {
		return name
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.seen[name]; ok {
		return name
	}
	if len(v.seen) >= maxVersionLabels {
		return versionOther
	}
	if v.seen == nil {
		v.seen = make(map[string]struct{}, maxVersionLabels)
	}
	v.seen[name] = struct{}{}
	return name
}

// maxVersionLength bounds one version label. A tag or a revision is shorter;
// anything longer is cut, so that a label value stays a label value.
const maxVersionLength = 32

// sanitizeVersion keeps a version string to what a build identifier is made
// of. Every other rune is dropped, an empty result becomes "unknown".
func sanitizeVersion(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '+':
		default:
			continue
		}
		if b.Len() >= maxVersionLength {
			break
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return versionUnknown
	}
	return b.String()
}
