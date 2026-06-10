package s5server

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/tlsdecoy"
	"github.com/mazixs/S5Core/pkg/transport/ws"
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
	ObfsEnabled      bool
	ObfsPort         string // Separate port for obfuscated connections
	ObfsPSK          string
	ObfsMaxPadding   int
	ObfsMTU          int
	ObfsReplayWindow int // Per-connection nonce replay window (0 = disabled)

	// WebSocket-over-TLS (stealth transport) settings
	WSEnabled     bool
	WSAddr        string // e.g. ":443"; if empty, uses ListenIP:443
	WSCertFile    string
	WSKeyFile     string
	WSPath        string
	WSSubprotocol string
	WSMinFrame    int           // minimum WS frame payload size (default 512)
	WSMaxFrame    int           // maximum WS frame payload size (default 4096)
	WSMaxJitter   time.Duration // max per-frame jitter (default 0)

	// Multi-account settings
	UsersFile            string        // Path to JSON file with user accounts
	TrafficFlushInterval time.Duration // Interval for flushing traffic counters to disk
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:             "1080",
		ListenIP:         "0.0.0.0",
		RequireAuth:      true,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		MaxConnections:   10000,
		Fail2BanRetries:  5,
		Fail2BanTime:     5 * time.Minute,
		ObfsReplayWindow: 2048,
	}
}

// ValidateConfig checks that the configuration is valid before starting the server.
func ValidateConfig(cfg Config) error {
	if cfg.ObfsEnabled {
		if len(cfg.ObfsPSK) != 32 {
			return fmt.Errorf("OBFS_PSK must be exactly 32 bytes, got %d", len(cfg.ObfsPSK))
		}
		if cfg.ObfsMaxPadding < 0 {
			return fmt.Errorf("OBFS_MAX_PADDING must be >= 0, got %d", cfg.ObfsMaxPadding)
		}
		if cfg.ObfsMaxPadding > 4096 {
			return fmt.Errorf("OBFS_MAX_PADDING must be <= 4096, got %d", cfg.ObfsMaxPadding)
		}
		if cfg.ObfsMTU < 0 {
			return fmt.Errorf("OBFS_MTU must be > 0, got %d", cfg.ObfsMTU)
		}
		if cfg.ObfsMTU > 0 && cfg.ObfsMTU < obfs.MinMTU {
			return fmt.Errorf("OBFS_MTU must be >= %d, got %d", obfs.MinMTU, cfg.ObfsMTU)
		}
	}
	if cfg.WSEnabled {
		if cfg.WSCertFile == "" || cfg.WSKeyFile == "" {
			return fmt.Errorf("WS_CERT_FILE and WS_KEY_FILE are required when WS_ENABLED is true")
		}
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
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

func (c *timeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("timeoutConn: underlying connection does not support CloseWrite")
}

// metricsConn is designed to count traffic and reduce GC using buffer pools.
type metricsConn struct {
	net.Conn
	telemetry *Telemetry
	closeOnce sync.Once
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
	c.closeOnce.Do(func() {
		if c.telemetry != nil {
			c.telemetry.ActiveConnections.Add(context.Background(), -1)
		}
	})
	return c.Conn.Close()
}

func (c *metricsConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("metricsConn: underlying connection does not support CloseWrite")
}

const fail2banShards = 256

type fail2banShard struct {
	mu          sync.RWMutex
	failures    map[string]int
	banned      map[string]time.Time
	lastCleanup time.Time
}

// fail2banStore implements socks5.CredentialStore with rate limiting and bans.
// It uses 256 sharded maps to eliminate the global lock bottleneck.
type fail2banStore struct {
	store      socks5.CredentialStore
	maxRetries int
	banTime    time.Duration
	telemetry  *Telemetry

	mu     sync.RWMutex // protects store mutations (AddUser / RemoveUser)
	shards [fail2banShards]fail2banShard
}

func newFail2banStore(store socks5.CredentialStore, maxRetries int, banTime time.Duration, t *Telemetry) *fail2banStore {
	f := &fail2banStore{
		store:      store,
		maxRetries: maxRetries,
		banTime:    banTime,
		telemetry:  t,
	}
	for i := range f.shards {
		f.shards[i] = fail2banShard{
			failures:    make(map[string]int),
			banned:      make(map[string]time.Time),
			lastCleanup: time.Now(),
		}
	}
	return f
}

func (s *fail2banStore) shardFor(key string) *fail2banShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &s.shards[h.Sum32()%fail2banShards]
}

func (s *fail2banStore) Valid(user, password string) bool {
	shard := s.shardFor(user)
	shard.mu.RLock()
	now := time.Now()

	if banExpiry, isBanned := shard.banned[user]; isBanned {
		if now.Before(banExpiry) {
			shard.mu.RUnlock()
			if s.telemetry != nil {
				s.telemetry.AuthFailures.Add(context.Background(), 1)
			}
			return false
		}
		// Expired ban: upgrade to write lock to clean it
		shard.mu.RUnlock()
		shard.mu.Lock()
		delete(shard.banned, user)
		delete(shard.failures, user)
		shard.mu.Unlock()
	} else {
		shard.mu.RUnlock()
	}

	// Heavy validation (Argon2id etc.) outside any lock
	valid := s.store.Valid(user, password)

	if !valid {
		shard.mu.Lock()
		shard.failures[user]++
		if shard.failures[user] >= s.maxRetries {
			shard.banned[user] = now.Add(s.banTime)
		}
		// Periodic cleanup of stale entries to prevent unbounded growth
		if now.Sub(shard.lastCleanup) > 5*time.Minute {
			s.cleanupShardLocked(shard, now)
			shard.lastCleanup = now
		}
		shard.mu.Unlock()
		if s.telemetry != nil {
			s.telemetry.AuthFailures.Add(context.Background(), 1)
		}
	} else {
		shard.mu.Lock()
		delete(shard.failures, user)
		shard.mu.Unlock()
	}

	return valid
}

func (s *fail2banStore) cleanupShardLocked(shard *fail2banShard, now time.Time) {
	for u, expiry := range shard.banned {
		if now.After(expiry) {
			delete(shard.banned, u)
			delete(shard.failures, u)
		}
	}
	// Heuristic: if failures map grew large, clear entries for users that are
	// not currently banned. This prevents memory exhaustion under random-username
	// brute-force attacks.
	if len(shard.failures) > s.maxRetries*100 {
		for u := range shard.failures {
			if _, banned := shard.banned[u]; !banned {
				delete(shard.failures, u)
			}
		}
	}
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

func (l *serverListener) setTimeouts(read, write time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.readTimeout = read
	l.writeTimeout = write
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
	psk           []byte
	maxPadding    int
	mtu           int
	replayWindow  int
}

func (ol *obfsListener) setTimeouts(read, write time.Duration) {
	ol.serverListener.setTimeouts(read, write)
}

func (ol *obfsListener) Accept() (net.Conn, error) {
	// Get a plain connection from the underlying serverListener
	conn, err := ol.serverListener.Accept()
	if err != nil {
		return nil, err
	}

	cfg := obfs.Config{
		PSK:          ol.psk,
		MaxPadding:   ol.maxPadding,
		MTU:          ol.mtu,
		ReplayWindow: ol.replayWindow,
	}

	obfsConn, err := obfs.NewConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("obfs: failed to wrap connection: %w", err)
	}

	return obfsConn, nil
}

// wsListener wraps a tlsdecoy.Listener and applies obfuscation on top of
// the WebSocket connection. This produces the full stealth stack:
// TLS -> WebSocket -> obfs -> SOCKS5.
type wsListener struct {
	*tlsdecoy.Listener
	psk          []byte
	maxPadding   int
	mtu          int
	replayWindow int
	wsMinFrame   int
	wsMaxFrame   int
	wsMaxJitter  time.Duration
}

func (wl *wsListener) Accept() (net.Conn, error) {
	conn, err := wl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if wsConn, ok := conn.(*ws.Conn); ok && wl.wsMaxFrame > 0 {
		conn = ws.NewShapedConn(wsConn, wl.wsMinFrame, wl.wsMaxFrame, wl.wsMaxJitter)
	}

	cfg := obfs.Config{
		PSK:          wl.psk,
		MaxPadding:   wl.maxPadding,
		MTU:          wl.mtu,
		ReplayWindow: wl.replayWindow,
	}

	obfsConn, err := obfs.NewConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("obfs: failed to wrap ws connection: %w", err)
	}

	return obfsConn, nil
}
