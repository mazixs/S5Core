package s5server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Telemetry holds OpenTelemetry instruments
type Telemetry struct {
	ActiveConnections metric.Int64UpDownCounter
	TotalConnections  metric.Int64Counter
	AuthFailures      metric.Int64Counter
	BytesIn           metric.Int64Counter
	BytesOut          metric.Int64Counter
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

	return &Telemetry{
		ActiveConnections: activeConns,
		TotalConnections:  totalConns,
		AuthFailures:      authFailures,
		BytesIn:           bytesIn,
		BytesOut:          bytesOut,
	}, nil
}

// Config represents the configuration for the SOCKS5 server.
type Config struct {
	Port            string
	ListenIP        string
	RequireAuth     bool
	AllowedDestFqdn string
	AllowedIPs      []string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	MaxConnections  int
	Fail2BanRetries int
	Fail2BanTime    time.Duration
	Logger          *slog.Logger
	Telemetry       *Telemetry // Optional custom telemetry

	// Obfuscation settings
	ObfsEnabled    bool
	ObfsPort       string // Separate port for obfuscated connections
	ObfsPSK        string
	ObfsMaxPadding int
	ObfsMTU        int

	// Multi-account settings
	UsersFile            string        // Path to JSON file with user accounts
	TrafficFlushInterval time.Duration // Interval for flushing traffic counters to disk
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:            "1080",
		ListenIP:        "0.0.0.0",
		RequireAuth:     true,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		MaxConnections:  10000,
		Fail2BanRetries: 5,
		Fail2BanTime:    5 * time.Minute,
	}
}

// timeoutConn wraps a net.Conn with read and write timeouts.
type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		err := c.SetReadDeadline(time.Now().Add(c.readTimeout))
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		err := c.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// metricsConn is designed to count traffic and reduce GC using buffer pools.
type metricsConn struct {
	net.Conn
	telemetry *Telemetry
}

func (c *metricsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.telemetry != nil && n > 0 {
		c.telemetry.BytesIn.Add(context.Background(), int64(n))
	}
	return n, err
}

func (c *metricsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.telemetry != nil && n > 0 {
		c.telemetry.BytesOut.Add(context.Background(), int64(n))
	}
	return n, err
}

func (c *metricsConn) ReadFrom(r io.Reader) (int64, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	var total int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := c.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (c *metricsConn) WriteTo(w io.Writer) (int64, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	var total int64
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (c *metricsConn) Close() error {
	if c.telemetry != nil {
		c.telemetry.ActiveConnections.Add(context.Background(), -1)
	}
	return c.Conn.Close()
}

// fail2banStore implements socks5.CredentialStore with rate limiting and bans.
type fail2banStore struct {
	store      socks5.CredentialStore
	maxRetries int
	banTime    time.Duration

	mu        sync.RWMutex
	failures  map[string]int
	banned    map[string]time.Time
	telemetry *Telemetry
}

func newFail2banStore(store socks5.CredentialStore, maxRetries int, banTime time.Duration, t *Telemetry) *fail2banStore {
	return &fail2banStore{
		store:      store,
		maxRetries: maxRetries,
		banTime:    banTime,
		failures:   make(map[string]int),
		banned:     make(map[string]time.Time),
		telemetry:  t,
	}
}

func (s *fail2banStore) Valid(user, password string) bool {
	s.mu.RLock()
	banExpiry, isBanned := s.banned[user]
	s.mu.RUnlock()

	if isBanned {
		if time.Now().Before(banExpiry) {
			if s.telemetry != nil {
				s.telemetry.AuthFailures.Add(context.Background(), 1)
			}
			return false
		}
		s.mu.Lock()
		delete(s.banned, user)
		delete(s.failures, user)
		s.mu.Unlock()
	}

	valid := s.store.Valid(user, password)

	if !valid {
		s.mu.Lock()
		s.failures[user]++
		if s.failures[user] >= s.maxRetries {
			s.banned[user] = time.Now().Add(s.banTime)
		}
		s.mu.Unlock()
		if s.telemetry != nil {
			s.telemetry.AuthFailures.Add(context.Background(), 1)
		}
	} else {
		s.mu.RLock()
		failures := s.failures[user]
		s.mu.RUnlock()

		if failures > 0 {
			s.mu.Lock()
			delete(s.failures, user)
			s.mu.Unlock()
		}
	}

	return valid
}

// serverListener wraps net.Listener to apply IP whitelisting and timeout wrappers.
type serverListener struct {
	net.Listener
	whitelist    []net.IP
	readTimeout  time.Duration
	writeTimeout time.Duration
	telemetry    *Telemetry
	mu           sync.RWMutex
}

func (l *serverListener) setWhitelist(ips []net.IP) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.whitelist = ips
}

func (l *serverListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		l.mu.RLock()
		whitelist := l.whitelist
		rt := l.readTimeout
		wt := l.writeTimeout
		l.mu.RUnlock()

		if len(whitelist) > 0 {
			host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				_ = conn.Close()
				continue
			}

			ip := net.ParseIP(host)
			if ip == nil {
				_ = conn.Close()
				continue
			}

			allowed := false
			for _, w := range whitelist {
				if ip.Equal(w) {
					allowed = true
					break
				}
			}

			if !allowed {
				_ = conn.Close()
				continue
			}
		}

		if rt > 0 || wt > 0 {
			conn = &timeoutConn{
				Conn:         conn,
				readTimeout:  rt,
				writeTimeout: wt,
			}
		}

		if l.telemetry != nil {
			ctx := context.Background()
			l.telemetry.ActiveConnections.Add(ctx, 1)
			l.telemetry.TotalConnections.Add(ctx, 1)
		}

		return &metricsConn{Conn: conn, telemetry: l.telemetry}, nil
	}
}

// obfsListener wraps a serverListener and applies obfuscation to accepted connections.
type obfsListener struct {
	*serverListener
	psk        []byte
	maxPadding int
	mtu        int
}

func (ol *obfsListener) Accept() (net.Conn, error) {
	// Get a plain connection from the underlying serverListener
	conn, err := ol.serverListener.Accept()
	if err != nil {
		return nil, err
	}

	cfg := obfs.Config{
		PSK:        ol.psk,
		MaxPadding: ol.maxPadding,
		MTU:        ol.mtu,
	}

	obfsConn, err := obfs.NewConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("obfs: failed to wrap connection: %w", err)
	}

	return obfsConn, nil
}
