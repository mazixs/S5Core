package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

const (
	Socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to slog.Default().
	Logger *slog.Logger

	// BytesAddIn is an optional high-performance callback to track inbound traffic metrics
	BytesAddIn func(int64)

	// BytesAddOut is an optional high-performance callback to track outbound traffic metrics
	BytesAddOut func(int64)

	// TrafficCounter resolves a username to a raw *atomic.Int64 pointer for
	// lock-free per-user traffic counting. It is called once per connection,
	// at setup, and both the TCP relay and the UDP associations count through
	// the pointer it returns.
	//
	// It is the only billing path. There used to be a second one for UDP - a
	// callback taking a username and a byte count - which meant one of the
	// two could be configured without the other, and one was: the callback
	// was invoked from the metrics code, so a deployment with no telemetry
	// billed no UDP traffic at all (F03 in
	// docs/reports/code-quality-audit-2026-09-20.md).
	TrafficCounter func(username string) *atomic.Int64

	// TunnelIdentity, when set, is asked who the transport underneath has
	// already authenticated, before any SOCKS5 method is negotiated. An
	// empty answer means the transport does not know, which is the case for
	// the plain listener and for a tunnel whose client has no key of its
	// own.
	//
	// A name from here outranks a password: the obfuscation layer checked a
	// MAC under that member's own key before the first frame was decrypted
	// (plan task Ф5-5), which is a stronger statement than a password, and
	// it costs the connection nothing. When it answers, the server offers
	// no-auth and uses the name it was given for quotas and accounting -
	// so Argon2id is left for the control panel, off the connection path
	// entirely.
	TunnelIdentity func(conn net.Conn) string

	// SessionStatus, when set, is asked whether an authenticated session may
	// continue, and if not, why. It is consulted on the traffic-flush
	// boundary the relay already has - every 64 KiB - and an answer other
	// than SessionAllowed ends the session: at once, or through a drain when
	// the connection's session grants one (plan task Ф6-1).
	//
	// Without it, quotas and expiry dates are checked once, at login: a
	// session that begins one byte under its limit runs to whatever size the
	// client wants. The account's own file then says it is out of quota while
	// it is still transferring.
	SessionStatus func(username string) SessionStatus

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// ObservePhase, when set, receives the duration of each finished
	// connection phase. See phase.go: this package measures, the caller
	// decides what a metric is.
	ObservePhase PhaseObserver

	// CountPhase, when set, tracks how many connections are currently in each
	// phase.
	CountPhase PhaseCounter

	// ObserveHalfClose, when set, is called with the outcome of every
	// half-close attempt towards a destination.
	ObserveHalfClose HalfCloseObserver
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = slog.Default()
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// handshakeBufferSize holds a whole SOCKS5 handshake: a 257-byte greeting, a
// 513-byte username/password exchange and a 262-byte request, plus room to
// spare. A client that sends them in one piece is then read in one syscall
// instead of eleven (plan task Ф6-5).
//
// The relay reads through the same buffer afterwards and pays nothing for it:
// bufio.Reader reads straight into the caller's slice when its own buffer is
// empty and the caller's is larger, which the relay's 32 KiB always is.
const handshakeBufferSize = 1088

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.ServeContext(context.Background(), l)
}

// ServeContext is used to serve connections from a listener with the given context.
func (s *Server) ServeContext(ctx context.Context, l net.Listener) error {
	live := newConnSet()

	// A cancelled context has to reach the connections, not only the
	// listener. Closing the listener stops new connections and does nothing
	// to the established ones: their handlers sit in io.Copy, and the process
	// either hangs waiting for them or exits with them still running, which
	// is the same leak seen from two sides.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			live.closeAll()
		case <-stopped:
		}
	}()

	var handlers sync.WaitGroup
	// ServeContext does not return until its handlers have: a caller that
	// gets a return value is entitled to assume the work has stopped.
	defer handlers.Wait()

	// How long the loop waits before trying a failure again, doubled on each
	// consecutive failure and reset by the first success.
	retryIn := time.Duration(0)

	for {
		conn, err := l.Accept()
		if err != nil {
			if recoverableAcceptError(err) {
				retryIn = nextAcceptRetry(retryIn)
				s.config.Logger.Warn("accept failed, listener stays up",
					"error", err, "retry_in", retryIn)
				timer := time.NewTimer(retryIn)
				select {
				case <-timer.C:
					continue
				case <-ctx.Done():
					timer.Stop()
				}
			}
			// The listener is finished, so the connections it produced are
			// finished too. Sessions here can be hours long; waiting for them
			// to end on their own is not shutting down.
			live.closeAll()
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		retryIn = 0

		if !live.add(conn) {
			// Shutdown started while this connection was in the accept queue.
			_ = conn.Close()
			continue
		}

		handlers.Add(1)
		go func(c net.Conn) {
			defer handlers.Done()
			defer live.remove(c)
			defer func() {
				if r := recover(); r != nil {
					s.config.Logger.Error("panic in socks5 handler", "recover", r)
				}
			}()
			_ = s.ServeConnContext(ctx, c)
		}(conn)
	}
}

// The accept loop's retry schedule. A descriptor shortage clears once the
// load drops, so the pause exists to stop the loop spinning through the
// backlog at full speed, and the ceiling exists so that a listener which
// recovers after a long outage is serving again within a second.
const (
	acceptRetryFirst = 5 * time.Millisecond
	acceptRetryMax   = time.Second
)

func nextAcceptRetry(current time.Duration) time.Duration {
	if current == 0 {
		return acceptRetryFirst
	}
	if next := current * 2; next < acceptRetryMax {
		return next
	}
	return acceptRetryMax
}

// recoverableAcceptError reports whether the next Accept on the same listener
// can succeed. Everything listed here is about this moment and not about the
// listening socket: the process is out of descriptors (EMFILE) or the system
// is (ENFILE), the kernel has no buffer space (ENOBUFS, ENOMEM), the client
// disappeared between SYN and accept (ECONNABORTED), or the call was
// interrupted (EINTR, EAGAIN). Returning from Accept on any of them takes the
// whole port down and keeps it down long after the cause has passed, which is
// an outage the server inflicts on itself.
//
// A closed listener is the opposite and must not be retried: it never comes
// back, and a retry loop over it spins.
func recoverableAcceptError(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, e := range recoverableAcceptErrnos {
		if errors.Is(err, e) {
			return true
		}
	}
	// A listener with a deadline set - only tests do this - reports the
	// expiry as a timeout, and the next call is expected to work.
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var recoverableAcceptErrnos = []error{
	syscall.EMFILE,
	syscall.ENFILE,
	syscall.ENOBUFS,
	syscall.ENOMEM,
	syscall.ECONNABORTED,
	syscall.EINTR,
	syscall.EAGAIN,
}

// connSet holds the connections a listener is currently serving, so that
// shutdown can reach them.
type connSet struct {
	mu      sync.Mutex
	closed  bool
	members map[net.Conn]struct{}
}

func newConnSet() *connSet {
	return &connSet{members: make(map[net.Conn]struct{})}
}

// add registers a connection and reports whether the set is still open. A
// false answer means shutdown has already run, and the caller owns the close.
func (s *connSet) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.members[c] = struct{}{}
	return true
}

func (s *connSet) remove(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.members, c)
}

// closeAll closes every live connection and marks the set closed, so a
// connection accepted after this point is not left behind.
func (s *connSet) closeAll() {
	s.mu.Lock()
	s.closed = true
	members := s.members
	s.members = make(map[net.Conn]struct{})
	s.mu.Unlock()

	for c := range members {
		_ = c.Close()
	}
}

// ServeConnContext is used to serve a single connection with the given context.
func (s *Server) ServeConnContext(ctx context.Context, conn net.Conn) (err error) {
	defer func() { _ = conn.Close() }()

	sessionPhase := s.startPhase(PhaseSession)
	defer func() { sessionPhase.end(err == nil) }()

	handshake := s.startPhase(PhaseHandshake)
	defer func() { handshake.end(false) }()

	// The connection's state machine, if the listener pipeline gave it one.
	// It is closed by the transport wrapper that owns it, on Close above.
	sess := session.Of(conn)
	started := time.Now()
	stage := "greeting"
	defer func() {
		if err == nil {
			return
		}
		err = connFailure(stage, "handle", err)
		var failure *ConnError
		if errors.As(err, &failure) {
			// No raw error: net.OpError may contain the client address.
			s.config.Logger.Debug("SOCKS5 connection failed",
				"stage", failure.Stage, "operation", failure.Op, "kind", failure.Kind,
				"transport", sess.Transport(), "protocol_state", sess.Protocol().String(),
				"handshake_budget", sess.SLA().Handshake, "elapsed", time.Since(started),
				"protocol_reason", protocolReason(err),
				"causes", failureCodes(err))
		}
	}()

	// The handshake is read through a buffer, not field by field off the
	// socket (plan task Ф6-5). A SOCKS5 handshake is a dozen fields of one
	// and two bytes, and reading each of them where it is used cost a read
	// per field - eleven syscalls before the first byte of payload. A client
	// that sends the handshake in one piece, which ours does, now costs one.
	//
	// The buffer outlives the handshake: whatever it read past the request -
	// a pipelining client's first bytes of payload - is handed to the relay
	// as Request.bufConn, so nothing that arrived early is lost.
	// One buffer per connection, and no pool. A pool was tried and is wrong
	// here: this function returns as soon as the context is cancelled, while
	// the relay goroutines are still reading through this buffer, so putting
	// it back would hand a live reader to the next connection. The race
	// detector says so, and a buffer of a kilobyte per connection is a poor
	// reason to invent a lifetime this code does not have.
	br := bufio.NewReaderSize(conn, handshakeBufferSize)

	// Read the version byte
	var version [1]byte
	if _, err := io.ReadFull(br, version[:]); err != nil {
		return connFailure("greeting", "version_read", err)
	}
	// The first byte is in: a peer that speaks. Everything up to the reply
	// to the request is the handshake.
	sess.Enter(session.Handshake)

	// Ensure we are compatible
	if version[0] != Socks5Version {
		return protocolFailure("greeting", "version_read", fmt.Errorf("unsupported SOCKS version: %v", version))
	}

	// Authenticate the connection. The handshake phase ends where credentials
	// start being read, so that password hashing is attributed to auth.
	stage = "auth"
	authContext, err := s.authenticate(conn, br, sourceOf(conn), s.tunnelIdentity(conn), handshake)
	if err != nil {
		return connFailure("auth", "exchange", err)
	}

	stage = "request"
	request, err := NewRequest(br)
	if err != nil {
		if errors.Is(err, errUnrecognizedAddrType) {
			if replyErr := sendReply(conn, addrTypeNotSupported, nil); replyErr != nil {
				return errors.Join(err, connFailure("request", "reply_write", replyErr))
			}
		}
		return fmt.Errorf("failed to read destination address: %w", err)
	}
	request.AuthContext = authContext
	request.session = sess
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(ctx, request, conn); err != nil {
		return connFailure("request", "handle", err)
	}

	return nil
}
