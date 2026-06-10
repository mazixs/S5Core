package tlsdecoy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// Listener is a net.Listener that accepts WebSocket connections over TLS
// while serving a decoy HTTP site on all other paths.
type Listener struct {
	tlsListener net.Listener
	conns       chan net.Conn
	server      *http.Server
	upgrader    *ws.Upgrader
}

// Config holds parameters for the TLS decoy listener.
type Config struct {
	Addr         string
	CertFile     string
	KeyFile      string
	WSPath       string
	DecoyHTML    string
	Subprotocols []string
}

// NewListener creates a TLS listener that serves a decoy site and upgrades
// WebSocket connections on the configured path.
func NewListener(cfg Config) (*Listener, error) {
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
		upgrader:    ws.NewUpgrader(ws.UpgraderOpts{Path: cfg.WSPath, Subprotocols: cfg.Subprotocols}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.WSPath, l.handleWS)
	mux.HandleFunc("/", l.handleDecoy(cfg.DecoyHTML))
	// Favicon and common paths to avoid 404 noise in logs
	mux.HandleFunc("/favicon.ico", l.handleFavicon)

	l.server = &http.Server{
		Handler: mux,
	}

	go func() {
		_ = l.server.Serve(tlsListener)
	}()

	return l, nil
}

// Accept returns a net.Conn for an accepted WebSocket connection.
func (l *Listener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, fmt.Errorf("tlsdecoy: listener closed")
	}
	return c, nil
}

// Close shuts down the listener and the underlying HTTP server.
func (l *Listener) Close() error {
	_ = l.server.Shutdown(context.Background())
	close(l.conns)
	return l.tlsListener.Close()
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
	l.conns <- c
}

func (l *Listener) handleDecoy(html string) http.HandlerFunc {
	if html == "" {
		html = defaultDecoyHTML
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	}
}

func (l *Listener) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
