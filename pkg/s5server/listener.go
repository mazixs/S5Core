package s5server

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type listenerPipeline struct {
	net.Listener
	transport string
	telemetry *Telemetry
	limiter   *connLimiter
	// sessions is where every accepted connection's state machine is opened
	// and registered, so the registry's Snapshot can count them by state. It
	// may be nil, in which case sessions are opened detached and counted by
	// nothing.
	sessions *session.Registry
	// framed says whether this transport carries obfuscation frames, i.e.
	// whether the session's frames region exists. It is set by withObfs.
	framed bool

	// shape runs on the raw connection, before the deadline wrapper: the
	// WebSocket shaper needs the concrete *ws.Conn, which any wrapper hides.
	shape func(net.Conn) net.Conn
	// wrap runs above the deadline wrapper, so obfuscation reads and writes
	// through the deadlines instead of around them. It gets the connection's
	// session, so the obfuscation layer can drive the frames region.
	wrap func(net.Conn, *session.Session) (net.Conn, error)
	// advice, when set, is asked at Accept time what the server currently
	// recommends to clients, so that a TRANSPORT_ADVICE changed on the fly
	// reaches the next connection rather than the next restart.
	advice func() *obfs.Advice

	// closeOnce makes Close idempotent. Both Start (on context cancellation)
	// and Stop close the listeners, and not every underlying listener
	// survives being closed twice - tlsdecoy closes a channel and panics on
	// the second call.
	closeOnce sync.Once
	closeErr  error

	// logger is where a refused connection says why. It is never nil:
	// Config gets a default logger before any listener is built.
	logger *slog.Logger

	// lastSetupLog and setupFailures rate limit that line. The cause of a
	// setup failure is the same for every connection that follows it, so an
	// unthrottled line per connection buries the server's own log under a
	// scanner or a bad reload.
	lastSetupLog  atomic.Int64
	setupFailures atomic.Int64

	mu               sync.RWMutex
	whitelist        []net.IP
	readTimeout      time.Duration
	writeTimeout     time.Duration
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	frameTimeout     time.Duration
	quotaGrace       time.Duration
}

// sla reads the budgets a new session on this listener lives under. The
// timeouts change on the fly (UpdateTimeouts, UpdateSessionTimeouts), so they
// are read under the lock, once per accepted connection.
func (l *listenerPipeline) sla() session.SLA {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return session.SLA{
		Handshake: l.handshakeTimeout,
		Dial:      l.dialTimeout,
		ReadIdle:  l.readTimeout,
		WriteIdle: l.writeTimeout,
		Grace:     l.quotaGrace,
		FrameBody: l.frameTimeout,
	}
}

func (l *listenerPipeline) Close() error {
	l.closeOnce.Do(func() { l.closeErr = l.Listener.Close() })
	return l.closeErr
}

// newListenerPipeline wraps a listener. The caller supplies the transport
// label and the stage functions; everything else is common.
func newListenerPipeline(l net.Listener, transport string, cfg Config, tel *Telemetry, limiter *connLimiter, sessions *session.Registry) *listenerPipeline {
	return &listenerPipeline{
		Listener:         l,
		transport:        transport,
		telemetry:        tel,
		limiter:          limiter,
		sessions:         sessions,
		logger:           cfg.Logger,
		readTimeout:      cfg.ReadTimeout,
		writeTimeout:     cfg.WriteTimeout,
		handshakeTimeout: cfg.HandshakeTimeout,
		dialTimeout:      cfg.DialTimeout,
		frameTimeout:     cfg.FrameTimeout,
		quotaGrace:       cfg.QuotaGrace,
	}
}

// withObfs adds the obfuscation layer above the deadlines. It marks the
// listener framed, so its sessions carry a frames region, and wires each
// connection's obfuscation reader to that region.
func (l *listenerPipeline) withObfs(cfg obfs.Config) *listenerPipeline {
	l.framed = true
	l.wrap = func(c net.Conn, sess *session.Session) (net.Conn, error) {
		perConn := cfg
		if l.advice != nil {
			perConn.Advice = l.advice()
		}
		perConn.OnFrameState = frameHook(sess)
		return obfs.NewServerConn(c, perConn)
	}
	return l
}

// frameHook translates the obfuscation reader's frame state into a move of
// the session's frames region. It runs on the reader's goroutine, once per
// change, and does nothing but a lock-free store, so it costs the hot path a
// map-free enum lookup and an atomic write.
func frameHook(sess *session.Session) func(obfs.FrameState) {
	if sess == nil {
		return nil
	}
	return func(s obfs.FrameState) {
		switch s {
		case obfs.FrameAwaitHeader:
			sess.Frame(session.AwaitHeader)
		case obfs.FrameAwaitBody:
			sess.Frame(session.AwaitBody)
		case obfs.FrameDelivered:
			sess.Frame(session.Deliver)
		case obfs.FrameRefused:
			sess.Frame(session.FrameError)
		}
	}
}

// withAdvice makes the obfuscation stage ask for the current transport
// advice on every accepted connection. Order does not matter: the function
// is consulted at Accept time, not now.
func (l *listenerPipeline) withAdvice(current func() *obfs.Advice) *listenerPipeline {
	l.advice = current
	return l
}

// withShaper adds WebSocket frame shaping below the deadlines.
func (l *listenerPipeline) withShaper(minFrame, maxFrame int, jitter time.Duration) *listenerPipeline {
	if maxFrame <= 0 {
		return l
	}
	l.shape = func(c net.Conn) net.Conn {
		wsConn, ok := c.(*ws.Conn)
		if !ok {
			return c
		}
		return ws.NewShapedConn(wsConn, minFrame, maxFrame, jitter)
	}
	return l
}

func (l *listenerPipeline) setWhitelist(ips []net.IP) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.whitelist = ips
}

func (l *listenerPipeline) setTimeouts(read, write time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.readTimeout = read
	l.writeTimeout = write
}

func (l *listenerPipeline) setHandshakeTimeout(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handshakeTimeout = d
}

func (l *listenerPipeline) setSessionTimeouts(dial, frame, grace time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dialTimeout = dial
	l.frameTimeout = frame
	l.quotaGrace = grace
}

func (l *listenerPipeline) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		l.mu.RLock()
		whitelist := l.whitelist
		l.mu.RUnlock()

		if !allowedByWhitelist(conn, whitelist) {
			_ = conn.Close()
			continue
		}

		if !l.limiter.acquire() {
			_ = conn.Close()
			l.countRejected(rejectAtLimit)
			continue
		}

		// The session exists from the accept onward, because the handshake
		// budget is counted from the accept and because a client that
		// connects and then says nothing is a state worth counting too.
		sess := l.sessions.Open(l.transport, l.framed, l.sla())

		if l.shape != nil {
			conn = l.shape(conn)
		}
		if l.limiter != nil {
			conn = &limitedConn{Conn: conn, limiter: l.limiter}
		}
		// Always: the session decides whether a deadline applies, and a
		// session with every budget at zero asks for none.
		conn = &timeoutConn{Conn: conn, sess: sess}
		if l.wrap != nil {
			wrapped, err := l.wrap(conn, sess)
			if err != nil {
				// One connection failed to get its transport wrapper. The
				// listener has nothing to do with it and stays up: this used
				// to return the error, and Serve treats an Accept error as
				// the end of the listener, so a single unwrappable
				// connection closed the port for everyone. The obfuscation
				// wrapper is rebuilt per connection from configuration that
				// SIGHUP can change, which is exactly when this happens -
				// and a reload is the worst moment to lose the port.
				_ = conn.Close()
				sess.Close()
				l.setupFailed(err)
				continue
			}
			conn = wrapped
		}

		return countAccepted(conn, sess, l.telemetry, l.transport), nil
	}
}

// Why a connection was refused on arrival. A closed set, two values: the
// server was full, or the connection could not be set up at all. The two need
// telling apart, because one is capacity and the other is a defect.
const (
	rejectAtLimit     = "limit"
	rejectSetupFailed = "setup_failed"
)

// countRejected records one connection refused on arrival.
func (l *listenerPipeline) countRejected(reason string) {
	if l.telemetry == nil || l.telemetry.ConnectionsRejected == nil {
		return
	}
	l.telemetry.ConnectionsRejected.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("transport", l.transport),
			attribute.String("reason", reason),
		))
}

// setupLogInterval is how often a setup failure may write a line. Everything
// in between is counted and reported with the next one.
const setupLogInterval = 5 * time.Second

// setupFailed counts a connection that could not be given its transport
// wrapper and, at most once per setupLogInterval, says so. The error text is
// the wrapper's own - it describes configuration, not the peer, and carries
// no address; see docs/design/observability-policy.md.
func (l *listenerPipeline) setupFailed(err error) {
	l.countRejected(rejectSetupFailed)
	l.setupFailures.Add(1)

	now := time.Now().UnixNano()
	last := l.lastSetupLog.Load()
	if now-last < int64(setupLogInterval) {
		return
	}
	// The loser of this race does not log: one line per interval, not one
	// per goroutine that noticed the interval had passed.
	if !l.lastSetupLog.CompareAndSwap(last, now) {
		return
	}
	if l.logger == nil {
		return
	}
	l.logger.Warn("Connection setup failed; the listener stays up",
		"transport", l.transport,
		"error", err,
		"failures_since_last", l.setupFailures.Swap(0))
}

// allowedByWhitelist reports whether the peer is on the list. An empty list
// means no restriction; an address that cannot be parsed is refused, because
// "cannot tell who this is" is not a reason to let it through.
//
// On the WebSocket transport the check lands after the upgrade, so the decoy
// site still answers every address. That is deliberate: a site that responds
// only to whitelisted addresses is a signature of its own, and the thing the
// whitelist protects is the tunnel, not the cover story.
func allowedByWhitelist(conn net.Conn, whitelist []net.IP) bool {
	if len(whitelist) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, w := range whitelist {
		if ip.Equal(w) {
			return true
		}
	}
	return false
}

// countAccepted registers an accepted connection under the transport it came
// in on and wraps it so that it is uncounted exactly once on close.
func countAccepted(conn net.Conn, sess *session.Session, t *Telemetry, transport string) net.Conn {
	label := metric.WithAttributes(attribute.String("transport", transport))
	if t != nil {
		ctx := context.Background()
		t.ActiveConnections.Add(ctx, 1, label)
		t.TotalConnections.Add(ctx, 1, label)
	}
	return &metricsConn{Conn: conn, sess: sess, telemetry: t, transport: label, transportName: transport}
}
