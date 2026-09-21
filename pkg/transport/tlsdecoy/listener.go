package tlsdecoy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	stdpath "path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// Listener is a net.Listener that accepts WebSocket connections over TLS
// while serving a decoy HTTP site on all other paths.
type Listener struct {
	tlsListener net.Listener
	conns       chan net.Conn
	server      *http.Server
	upgrader    *ws.Upgrader

	// done is closed exactly once, by Close. The handover channel is never
	// closed: an upgrade handler may be about to send on it, and closing a
	// channel underneath a sender is a panic - a crash on shutdown, in the
	// one code path that runs on every deployment.
	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// Config holds parameters for the TLS decoy listener.
type Config struct {
	Addr     string
	CertFile string
	KeyFile  string
	WSPath   string
	// DecoyHTML is the built-in page served when there is no upstream.
	DecoyHTML string
	// DecoyUpstream, when set, is the site every non-tunnel request is
	// proxied to (plan task Ф5-6). It replaces DecoyHTML entirely: the
	// upstream answers for the root, for unknown paths and for the
	// tunnel's own path when the request is not a WebSocket upgrade.
	DecoyUpstream string
	Subprotocols  []string
	// Logger receives upstream failures. Nil means slog.Default.
	Logger *slog.Logger
}

// Timeouts for the decoy HTTP server. Without them a handful of sockets that
// open and never finish a request holds the decoy indefinitely - and the decoy
// is the part of this transport that faces the open internet.
//
// They apply to HTTP requests only: the WebSocket upgrade hijacks the
// connection and clears its deadlines, after which the tunnel's own timeouts
// take over.
const (
	decoyReadHeaderTimeout = 10 * time.Second
	decoyReadTimeout       = 30 * time.Second
	decoyWriteTimeout      = 30 * time.Second
	decoyIdleTimeout       = 60 * time.Second
)

// ValidatePath reports whether a path can serve as the WebSocket endpoint.
//
// What it accepts is one exact, literal, already-canonical path, because that
// is the only thing the two sides of this listener agree on. The path is used
// twice: as a net/http.ServeMux pattern here, and as an exact comparison
// against r.URL.Path in ws.Upgrader. A ServeMux pattern is a small language -
// it has wildcards, a host part and a method part - and anything that uses
// that language matches requests here that the upgrader then refuses, so the
// tunnel is registered and unreachable. Worse, a pattern the language cannot
// parse is a panic: net/http documents ServeMux.Handle as panicking on a bad
// pattern, and the listener's socket is already open by then, so a
// configuration mistake became a crash with a message about mux registration
// (F16 in docs/reports/code-quality-audit-2026-09-20.md).
//
// The checks are therefore in two parts: named rules, which produce an error
// that says what to fix, and one last question put to net/http itself, which
// catches whatever its pattern language grows next.
func ValidatePath(path string) error {
	switch {
	case path == "":
		return errors.New("tlsdecoy: WebSocket path is empty, use something like /ws")
	case !strings.HasPrefix(path, "/"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q must start with /", path)
	case path == "/":
		return errors.New(`tlsdecoy: WebSocket path cannot be "/" - that is the decoy site's own path`)
	case path == "/favicon.ico":
		return errors.New("tlsdecoy: WebSocket path cannot be /favicon.ico - the decoy serves it")
	case strings.HasSuffix(path, "/"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q must not end with / - a trailing slash claims the whole subtree and hides it from the decoy", path)
	case strings.ContainsAny(path, " \t"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q must not contain whitespace", path)
	case strings.ContainsAny(path, "{}"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q uses the ServeMux wildcard syntax; the endpoint is compared literally, so a wildcard matches requests the upgrade then refuses", path)
	case strings.ContainsAny(path, "?#"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q contains %q or %q, which are not part of a path - the query and the fragment never reach the server's path comparison", path, "?", "#")
	case strings.Contains(path, "%"):
		return fmt.Errorf("tlsdecoy: WebSocket path %q is percent-encoded; the comparison is against the decoded path, so write the decoded form", path)
	}

	if i := strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
		return fmt.Errorf("tlsdecoy: WebSocket path %q contains a control character at offset %d", path, i)
	}
	if cleaned := stdpath.Clean(path); cleaned != path {
		return fmt.Errorf("tlsdecoy: WebSocket path %q is not canonical (net/http would redirect it to %q, and the upgrade compares the path exactly)", path, cleaned)
	}

	return registrable(path)
}

// registrable asks net/http whether it would accept this pattern, by
// registering it on a throwaway mux and catching the panic its documentation
// promises. Asking is better than predicting: the pattern language gained
// wildcards in Go 1.22 and the rules above would have been silently
// incomplete for a release.
func registrable(pattern string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tlsdecoy: WebSocket path %q is not a pattern net/http accepts: %v", pattern, r)
		}
	}()
	http.NewServeMux().Handle(pattern, http.NotFoundHandler())
	return nil
}

// NewListener creates a TLS listener that serves a decoy site and upgrades
// WebSocket connections on the configured path.
func NewListener(cfg Config) (*Listener, error) {
	if err := ValidatePath(cfg.WSPath); err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsdecoy: failed to load certificates: %w", err)
	}
	tlsConf.Certificates = []tls.Certificate{cert}

	plainListener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("tlsdecoy: failed to listen: %w", err)
	}
	tlsListener := tls.NewListener(plainListener, tlsConf)

	l := &Listener{
		tlsListener: tlsListener,
		conns:       make(chan net.Conn, 64),
		done:        make(chan struct{}),
		upgrader:    ws.NewUpgrader(ws.UpgraderOpts{Path: cfg.WSPath, Subprotocols: cfg.Subprotocols}),
	}

	decoy, err := newDecoyHandler(cfg)
	if err != nil {
		_ = tlsListener.Close()
		return nil, err
	}

	mux := http.NewServeMux()
	// The tunnel's path answers the tunnel only when the request is a
	// WebSocket upgrade. Everything else on it goes to the decoy, so a
	// plain GET of the path gets exactly what a plain GET of any other
	// path gets - which is what keeps the endpoint from being found by
	// asking for it (plan task Ф5-6).
	mux.HandleFunc(cfg.WSPath, func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			l.handleWS(w, r)
			return
		}
		decoy.ServeHTTP(w, r)
	})
	mux.Handle("/", decoy)

	l.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: decoyReadHeaderTimeout,
		ReadTimeout:       decoyReadTimeout,
		WriteTimeout:      decoyWriteTimeout,
		IdleTimeout:       decoyIdleTimeout,
	}

	go func() {
		_ = l.server.Serve(tlsListener)
	}()

	return l, nil
}

// Accept returns a net.Conn for an accepted WebSocket connection. After Close
// it returns net.ErrClosed, which is what callers already treat as "this
// listener is finished".
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close shuts down the listener and the underlying HTTP server. It is safe to
// call more than once and safe to call while an upgrade is in flight: done is
// what releases a handler waiting to hand its connection over, and nothing
// closes the handover channel.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.server.Shutdown(context.Background())
		if err := l.tlsListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.closeErr = err
		}
		// Connections that were handed over but never accepted belong to
		// nobody now, so this is the last chance to close them.
		for {
			select {
			case c := <-l.conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return l.closeErr
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.tlsListener.Addr()
}

func (l *Listener) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := l.upgrader.Upgrade(w, r)
	if err != nil {
		// Upgrader already wrote an HTTP error response.
		return
	}
	select {
	case l.conns <- c:
	case <-l.done:
		// The listener closed between the upgrade and the handover. The
		// connection is ours to close; before, this send raced with
		// close(l.conns) and crashed the process.
		_ = c.Close()
	}
}

// newDecoyHandler is what answers everything that is not the tunnel: the
// upstream site when one is configured, the built-in page otherwise.
func newDecoyHandler(cfg Config) (http.Handler, error) {
	target, err := ValidateUpstream(cfg.DecoyUpstream)
	if err != nil {
		return nil, err
	}
	if target != nil {
		return newDecoyProxy(target, cfg.Logger), nil
	}
	return staticDecoy(cfg.DecoyHTML), nil
}

// staticDecoy is the built-in page: one landing page at the root, an empty
// favicon, and a 404 for everything else. It is the fallback for a
// deployment that has no site to mirror; docs/design/decoy.md says what it costs.
func staticDecoy(html string) http.HandlerFunc {
	if html == "" {
		html = defaultDecoyHTML
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
		case "/favicon.ico":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}
}
