package s5server

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Telemetry holds OpenTelemetry instruments
type Telemetry struct {
	ActiveConnections metric.Int64UpDownCounter
	TotalConnections  metric.Int64Counter
	AuthFailures      metric.Int64Counter
	BytesIn           metric.Int64Counter
	BytesOut          metric.Int64Counter

	// ObfsFailures counts frame-level obfuscation failures. Its only labels are
	// reason and transport - both come from a fixed set inside this process, so
	// the metric cannot leak a peer address or blow up in cardinality. See
	// docs/design/observability-policy.md.
	ObfsFailures metric.Int64Counter
	// ObfsBytesBeforeFailure records how many bytes arrived on a connection
	// before it was rejected. A probe that gives up on the first frame and a
	// client with a wrong PSK that keeps sending look different here.
	ObfsBytesBeforeFailure metric.Int64Histogram
	// ObfsClockSkew counts connections refused because the peer's clock is
	// outside the epoch window (plan task Ф5-3). Without it a device whose
	// clock never synchronised is indistinguishable from a scanner in the
	// failure counter, and the operator has nothing to act on. Labels are
	// transport and direction (ahead or behind) - the exact number of hours
	// goes to the log, not to a label, because it is unbounded.
	ObfsClockSkew metric.Int64Counter

	// PhaseDuration records how long each stage of a connection took, labelled
	// by phase and outcome. Five phases, so five distributions from one
	// instrument: handshake, auth, dial, first_byte, session.
	PhaseDuration metric.Float64Histogram
	// ConnectionsInPhase is how many connections sit in each phase right now.
	// A backlog in one phase is the signal; the total is not interesting.
	ConnectionsInPhase metric.Int64UpDownCounter

	// BuildInfo is the conventional always-1 gauge carrying the build identity
	// and the set of transports this process actually listens on.
	BuildInfo metric.Int64UpDownCounter

	// AuthVerifications counts password checks by the path that answered
	// them: kdf when Argon2id ran, cache when the in-memory verifier did,
	// coalesced when the check waited for a KDF run already in flight, and
	// overloaded when the KDF memory budget was full and the check was
	// refused without running (F06). The
	// ratio is the health of the fix from task Ф3-6 - a server whose kdf rate
	// tracks its connection rate has lost the cache and is back to 110 ms and
	// 64 MiB per login. No user name or address is attached; see
	// docs/design/observability-policy.md.
	AuthVerifications metric.Int64Counter

	// AuthAccountAlerts counts accounts that crossed the soft failure limit:
	// somebody is working through passwords for a named account, possibly
	// from many addresses at once. It is an alert, not a lockout - the owner
	// is never refused because of it. No user name or address is attached.
	AuthAccountAlerts metric.Int64Counter

	// HalfCloseFailures counts connections whose write side could not be shut
	// down, by side and transport. Half-close works over plain TCP and obfs,
	// and does not exist over WebSocket, so this is where that difference
	// stops being folklore and becomes a number.
	HalfCloseFailures metric.Int64Counter

	// ConnectionsRejected counts connections closed on arrival, by transport
	// and by reason: the server was at MAX_CONNECTIONS ("limit"), or the
	// connection could not be set up at all ("setup_failed"). Without it a
	// server at its ceiling looks exactly like a server nobody is using:
	// the connection count stops rising and nothing else says why. The
	// reason separates that from a listener that is up and refusing every
	// connection it accepts, which is a defect and not capacity.
	ConnectionsRejected metric.Int64Counter

	// ClientConnections counts tunnels whose client introduced itself, by
	// the client's build and the transport it arrived on (plan task Ф5-7).
	// This is the distribution a migration is steered by: which versions
	// are still out there, and whether a transport advice is being
	// followed. Clients that send no hello - older builds - are the gap
	// between this and s5core_connections_total on the same transport.
	ClientConnections metric.Int64Counter

	// Sessions is how many connections sit in each state of each region
	// right now, labelled by region, state and transport (plan task Ф6-1).
	// It is the metric the bug report needed: a third of the connections
	// parked in the protocol region's dialing state while the relay state
	// looks healthy is the picture of a destination that does not answer.
	// It is observable because the truth lives in the session registry: the
	// hot path pays one atomic store per transition and nothing per scrape.
	Sessions metric.Int64ObservableGauge
	// SessionTransitions counts the moves themselves, by region, from, to
	// and transport. The gauge says where connections are, this says how
	// they got there - a rate of relay->half_closed is a quota biting, and
	// an illegal transition is a driver bug that is now counted rather than
	// guessed at. Every label comes from a closed enum in the code; see
	// docs/design/observability-policy.md.
	SessionTransitions metric.Int64Counter

	// meter is kept so that the session gauge can be registered once the
	// registry that answers it exists, which is in NewServer.
	meter metric.Meter
}

// InitTelemetry initializes standard OpenTelemetry metrics
func InitTelemetry(meterProvider metric.MeterProvider) (*Telemetry, error) {
	if meterProvider == nil {
		meterProvider = otel.GetMeterProvider()
	}
	meter := meterProvider.Meter("github.com/mazixs/S5Core")

	activeConns, err := meter.Int64UpDownCounter("s5core_connections_active", metric.WithDescription("The total number of active connections"))
	if err != nil {
		return nil, err
	}

	totalConns, err := meter.Int64Counter("s5core_connections_total", metric.WithDescription("The total number of handled connections"))
	if err != nil {
		return nil, err
	}

	authFailures, err := meter.Int64Counter("s5core_auth_failures_total", metric.WithDescription("The total number of failed authentications"))
	if err != nil {
		return nil, err
	}

	bytesIn, err := meter.Int64Counter("s5core_traffic_bytes_in", metric.WithDescription("Total bytes transferred in"))
	if err != nil {
		return nil, err
	}

	bytesOut, err := meter.Int64Counter("s5core_traffic_bytes_out", metric.WithDescription("Total bytes transferred out"))
	if err != nil {
		return nil, err
	}

	obfsFailures, err := meter.Int64Counter("s5core_obfs_handshake_failures_total",
		metric.WithDescription("Obfuscated frames rejected, by failure reason"))
	if err != nil {
		return nil, err
	}

	obfsBytes, err := meter.Int64Histogram("s5core_obfs_bytes_before_failure",
		metric.WithDescription("Bytes received on a connection before an obfuscation failure"),
		metric.WithUnit("By"),
		metric.WithExplicitBucketBoundaries(0, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576))
	if err != nil {
		return nil, err
	}

	phaseDuration, err := meter.Float64Histogram("s5core_connection_phase_seconds",
		metric.WithDescription("Duration of each connection lifecycle phase"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025,
			0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))
	if err != nil {
		return nil, err
	}

	connectionsInPhase, err := meter.Int64UpDownCounter("s5core_connections_in_phase",
		metric.WithDescription("Connections currently sitting in each lifecycle phase"))
	if err != nil {
		return nil, err
	}

	buildInfo, err := meter.Int64UpDownCounter("s5core_build_info",
		metric.WithDescription("Always 1; labels carry the build identity and the enabled transports"))
	if err != nil {
		return nil, err
	}

	authVerifications, err := meter.Int64Counter("s5core_auth_verifications_total",
		metric.WithDescription("Password checks, by the path that answered them: kdf, cache, coalesced or overloaded"))
	if err != nil {
		return nil, err
	}

	authAccountAlerts, err := meter.Int64Counter("s5core_auth_account_alerts_total",
		metric.WithDescription("Accounts that crossed the soft authentication failure limit"))
	if err != nil {
		return nil, err
	}

	halfCloseFailures, err := meter.Int64Counter("s5core_half_close_failures_total",
		metric.WithDescription("Half-close attempts that failed, by side and transport"))
	if err != nil {
		return nil, err
	}

	connectionsRejected, err := meter.Int64Counter("s5core_connections_rejected_total",
		metric.WithDescription("Connections closed on arrival, by transport and reason (limit, setup_failed)"))
	if err != nil {
		return nil, err
	}

	obfsClockSkew, err := meter.Int64Counter("s5core_obfs_clock_skew_total",
		metric.WithDescription("Connections refused because the peer's clock is outside the epoch window, by transport and direction"))
	if err != nil {
		return nil, err
	}

	clientConnections, err := meter.Int64Counter("s5core_client_connections_total",
		metric.WithDescription("Tunnels whose client introduced itself, by client build and transport"))
	if err != nil {
		return nil, err
	}

	// Observable: the registry already knows the answer, so asking it at
	// scrape time is cheaper and more honest than keeping a counter per
	// state in step with every transition.
	sessions, err := meter.Int64ObservableGauge("s5core_sessions",
		metric.WithDescription("Connections currently in each state of each session region, by transport"))
	if err != nil {
		return nil, err
	}

	sessionTransitions, err := meter.Int64Counter("s5core_session_transitions_total",
		metric.WithDescription("Session state transitions, by region, source state, target state and transport"))
	if err != nil {
		return nil, err
	}

	return &Telemetry{
		ActiveConnections: activeConns,
		TotalConnections:  totalConns,
		AuthFailures:      authFailures,
		BytesIn:           bytesIn,
		BytesOut:          bytesOut,

		ObfsFailures:           obfsFailures,
		ObfsBytesBeforeFailure: obfsBytes,
		ObfsClockSkew:          obfsClockSkew,

		PhaseDuration:      phaseDuration,
		ConnectionsInPhase: connectionsInPhase,
		BuildInfo:          buildInfo,
		AuthVerifications:  authVerifications,
		AuthAccountAlerts:  authAccountAlerts,
		HalfCloseFailures:  halfCloseFailures,

		ConnectionsRejected: connectionsRejected,
		ClientConnections:   clientConnections,

		Sessions:           sessions,
		SessionTransitions: sessionTransitions,
		meter:              meter,
	}, nil
}

// sessionTransitionObserver turns every state change of every session into a
// counter increment. It runs on the goroutine that made the transition - a
// relay goroutine, or the obfuscation reader for the frames region - so it
// does nothing but add to a counter with attributes from closed enums.
func sessionTransitionObserver(t *Telemetry) session.Observer {
	if t == nil || t.SessionTransitions == nil {
		return nil
	}
	return func(tr session.Transition) {
		t.SessionTransitions.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("region", tr.Region.String()),
			attribute.String("from", tr.FromName()),
			attribute.String("to", tr.ToName()),
			attribute.String("transport", tr.Transport),
			attribute.Bool("illegal", tr.Illegal),
		))
	}
}

// registerSessionGauge makes the session registry answer the s5core_sessions
// gauge at scrape time. The returned registration is unregistered on Stop, so
// that a server started and stopped inside one process - a test, an embedder
// restarting the SDK - does not leave a callback pointing at a dead registry.
func registerSessionGauge(t *Telemetry, reg *session.Registry) (metric.Registration, error) {
	if t == nil || t.Sessions == nil || t.meter == nil || reg == nil {
		return nil, nil
	}
	return t.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			for _, c := range reg.Snapshot() {
				o.ObserveInt64(t.Sessions, c.N, metric.WithAttributes(
					attribute.String("region", c.Region.String()),
					attribute.String("state", c.StateName()),
					attribute.String("transport", c.Transport),
				))
			}
			return nil
		},
		t.Sessions,
	)
}

// Sides of a proxied connection, used as a metric label.
const (
	SideClient = "client"
	SideTarget = "target"
)

// recordHalfCloseFailure counts one connection that could not be half-closed.
func (t *Telemetry) recordHalfCloseFailure(side, transport string) {
	if t == nil || t.HalfCloseFailures == nil {
		return
	}
	t.HalfCloseFailures.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("side", side),
		attribute.String("transport", transport),
	))
}

// authVerifyObserver reports which path answered a password check. It runs on
// the connection goroutine, so it does nothing but increment a counter.
func authVerifyObserver(t *Telemetry) func(userstore.VerifyPath) {
	if t == nil || t.AuthVerifications == nil {
		return nil
	}
	labels := map[userstore.VerifyPath]metric.MeasurementOption{
		userstore.VerifyPathKDF:        metric.WithAttributes(attribute.String("path", string(userstore.VerifyPathKDF))),
		userstore.VerifyPathCache:      metric.WithAttributes(attribute.String("path", string(userstore.VerifyPathCache))),
		userstore.VerifyPathCoalesced:  metric.WithAttributes(attribute.String("path", string(userstore.VerifyPathCoalesced))),
		userstore.VerifyPathOverloaded: metric.WithAttributes(attribute.String("path", string(userstore.VerifyPathOverloaded))),
	}
	return func(path userstore.VerifyPath) {
		label, ok := labels[path]
		if !ok {
			return
		}
		t.AuthVerifications.Add(context.Background(), 1, label)
	}
}

// halfCloseHook counts failures on the destination side. The destination is
// always a plain TCP connection today, so its transport label is constant.
// authHooks turns the telemetry into the two callbacks internal/identity
// reports through. The guard counts refusals and alerts; what a count is, is
// this package's business, which is the whole point of the split.
func authHooks(t *Telemetry) (failure, alert func()) {
	if t == nil {
		return nil, nil
	}
	if t.AuthFailures != nil {
		failure = func() { t.AuthFailures.Add(context.Background(), 1) }
	}
	if t.AuthAccountAlerts != nil {
		alert = func() { t.AuthAccountAlerts.Add(context.Background(), 1) }
	}
	return failure, alert
}

func halfCloseHook(t *Telemetry) socks5.HalfCloseObserver {
	if t == nil || t.HalfCloseFailures == nil {
		return nil
	}
	return func(err error) {
		if err != nil {
			t.recordHalfCloseFailure(SideTarget, "tcp")
		}
	}
}

// RecordBuildInfo publishes the build identity and the transports that are
// actually listening. Both are properties of this process, not of any client,
// and both are constant for its lifetime.
//
// It exists because "the server is running the new version" and "the server is
// actually listening on the stealth transport" are the two claims that are
// impossible to check from outside and easiest to get wrong.
func (t *Telemetry) RecordBuildInfo(version, goVersion string, transports []string) {
	if t == nil || t.BuildInfo == nil {
		return
	}
	list := "none"
	if len(transports) > 0 {
		list = strings.Join(transports, ",")
	}
	t.BuildInfo.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("version", version),
		attribute.String("go_version", goVersion),
		attribute.String("transports", list),
	))
}

// phaseHooks builds the callbacks that internal/socks5 uses to report the
// lifecycle of a connection. Both labels - phase and outcome - come from closed
// sets in the code, never from the peer.
func phaseHooks(t *Telemetry) (socks5.PhaseObserver, socks5.PhaseCounter) {
	if t == nil || t.PhaseDuration == nil || t.ConnectionsInPhase == nil {
		return nil, nil
	}

	observe := func(phase socks5.Phase, d time.Duration, ok bool) {
		outcome := "ok"
		if !ok {
			outcome = "fail"
		}
		t.PhaseDuration.Record(context.Background(), d.Seconds(), metric.WithAttributes(
			attribute.String("phase", string(phase)),
			attribute.String("outcome", outcome),
		))
	}

	count := func(phase socks5.Phase, delta int64) {
		t.ConnectionsInPhase.Add(context.Background(), delta, metric.WithAttributes(
			attribute.String("phase", string(phase)),
		))
	}

	return observe, count
}

// obfsFailureObserver builds the callback that pkg/obfs invokes once per
// connection when a frame is rejected. transport is a compile-time constant of
// this package, never data taken from the peer.
//
// Nothing here touches the remote address: the whole point of the metric is to
// tell "a probe knocked" from "a client has the wrong PSK" without keeping a
// list of who knocked.
func obfsFailureObserver(t *Telemetry, logger *slog.Logger, transport string) obfs.FailureObserver {
	return func(fe *obfs.FrameError) {
		if fe == nil {
			return
		}
		if t != nil && t.ObfsFailures != nil {
			attrs := metric.WithAttributes(
				attribute.String("reason", string(fe.Reason)),
				attribute.String("transport", transport),
			)
			ctx := context.Background()
			t.ObfsFailures.Add(ctx, 1, attrs)
			if t.ObfsBytesBeforeFailure != nil {
				t.ObfsBytesBeforeFailure.Record(ctx, fe.BytesBefore, attrs)
			}
		}
		if logger != nil {
			logger.Debug("Obfuscated frame rejected",
				"reason", string(fe.Reason),
				"bytes_before", fe.BytesBefore,
				"transport", transport,
			)
		}
	}
}

// obfsClockSkewObserver reports a peer whose clock is too far out to derive
// the same keys. The connection is refused regardless and on the wire the
// refusal is the same one a wrong PSK gets: this only makes the cause
// visible on the server, where an operator can act on it.
func obfsClockSkewObserver(t *Telemetry, logger *slog.Logger, transport string) func(int64) {
	return func(epochs int64) {
		direction := "behind"
		if epochs > 0 {
			direction = "ahead"
		}
		if t != nil && t.ObfsClockSkew != nil {
			t.ObfsClockSkew.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("transport", transport),
				attribute.String("direction", direction),
			))
		}
		if logger != nil {
			logger.Warn("Peer clock is out of step; connection refused",
				"hours", epochs,
				"transport", transport,
			)
		}
	}
}

// Config represents the configuration for the SOCKS5 server.
