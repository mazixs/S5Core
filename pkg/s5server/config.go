package s5server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/tlsdecoy"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

type Config struct {
	Port            string
	ListenIP        string
	RequireAuth     bool
	AllowedDestFqdn string
	AllowedIPs      []string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	// HandshakeTimeout caps how long the whole setup may take: version byte,
	// authentication and the reply to CONNECT. It is an absolute budget, not
	// an idle timeout, because a client that sends one byte per second keeps
	// an idle timeout alive forever. Zero selects DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// DialTimeout bounds one connection attempt to the destination. Without
	// it the attempt runs on the operating system's own timeout - over two
	// minutes on Linux - and every one of those minutes is a client parked in
	// the Dialing state waiting for its reply to CONNECT, which is bug 1 of
	// the bug report (plan task Ф6-1). Zero selects DefaultDialTimeout.
	DialTimeout time.Duration
	// FrameTimeout is how long an obfuscation frame may stay incomplete once
	// its header has arrived. It is the per-frame deadline that applies even
	// to a tunnel, which otherwise lives under no idle timeout at all. Zero
	// selects DefaultFrameTimeout.
	FrameTimeout time.Duration
	// QuotaGrace is how long a session keeps draining after its account ran
	// out, so that what the destination has already sent still reaches the
	// client before the session is cut. Zero ends the session where the quota
	// is noticed, which is the historical behaviour.
	QuotaGrace time.Duration
	// Dial, when set, replaces the dialer the relay reaches destinations
	// with. An embedder uses it to route through its own network stack; a
	// test uses it to hold a connection in the Dialing state on purpose.
	// Nil is the plain system dialer.
	Dial            func(ctx context.Context, network, addr string) (net.Conn, error)
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
	// ObfsReplayWindow is how many session salts the server remembers, across
	// all obfuscated listeners, to recognise a recorded connection sent again.
	// Zero disables the check. It used to be a per-connection nonce window,
	// which cost 82 KiB per connection and could not see across connections -
	// the only place a replay actually happens.
	ObfsReplayWindow int

	// ObfsNodeID is this node's identity in the key derivation. It is never
	// on the wire: it goes into the prologue MAC and the HKDF labels, so a
	// client configured for another node is refused exactly the way noise is
	// refused (plan task Ф5-4). Empty means unbound.
	//
	// The price is deliberate: anycast and moving a client between nodes
	// without touching its configuration stop working. What it buys is that
	// a recording made against one node is worthless against another, so no
	// node needs to know what the others have seen.
	ObfsNodeID string
	// ObfsAcceptNodeIDs are the other identities this node still answers to
	// while clients are being migrated. One extra HMAC per connection each.
	ObfsAcceptNodeIDs []string
	// ObfsRequireMemberKey drops the shared account: only clients holding
	// a per-user tunnel key may connect (plan task Ф5-5). It is the far end
	// of a migration - turn it on once every client in the field has a key,
	// and a stolen PSK alone stops being enough to reach the server.
	ObfsRequireMemberKey bool

	// ObfsKeepaliveMin and ObfsKeepaliveMax make the server send a frame
	// carrying nothing after a silence drawn from that range, so that a box on
	// the path does not drop a connection it believes is dead. Zero, the
	// default, leaves it to the client: one end holding the path open is
	// enough, and the frames the other end would add are traffic that buys
	// nothing. Set it when the clients are not s5client and do not send
	// keepalives of their own.
	ObfsKeepaliveMin time.Duration
	ObfsKeepaliveMax time.Duration

	// WebSocket-over-TLS (stealth transport) settings
	WSEnabled     bool
	WSAddr        string // e.g. ":443"; if empty, uses ListenIP:443
	WSCertFile    string
	WSKeyFile     string
	WSPath        string
	WSSubprotocol string
	// WSDecoyUpstream is the site every non-tunnel request on the WS
	// listener is proxied to (plan task Ф5-6). Empty serves the built-in
	// page instead, which is weaker cover - see docs/design/decoy.md.
	WSDecoyUpstream string
	// TransportAdvice is what the server tells every client inside the
	// tunnel, once it is up: which transport to use next and what shape
	// to give its traffic (plan task Ф5-7). It is how a client on a router
	// changes transport without anyone touching the router. The syntax is
	// in ParseTransportAdvice; empty sends nothing. Changed on the fly by
	// UpdateTransportAdvice.
	TransportAdvice string
	// The shaping band. The defaults belong to the shaper itself
	// (DefaultWSMinFrame and DefaultWSMaxFrame below, which are
	// ws.DefaultMinFrame and ws.DefaultMaxFrame), because the numbers only
	// mean anything against its cut rules - see pkg/transport/ws/shaped.go
	// and docs/benchmarks/frame-shaping.md. Naming a number here instead is
	// how this comment came to promise 512 while the shaper used 256.
	WSMinFrame  int           // minimum WS frame payload size
	WSMaxFrame  int           // maximum WS frame payload size
	WSMaxJitter time.Duration // max per-frame jitter (default 0)

	// Multi-account settings
	UsersFile            string        // Path to JSON file with user accounts
	TrafficFlushInterval time.Duration // Interval for flushing traffic counters to disk

	// KDFMemoryBudget bounds the memory concurrent password checks may use,
	// in bytes. Argon2id asks for 64 MiB a run, and the number of runs is
	// chosen by whoever opens connections, so the bound is on memory rather
	// than on connections (F06). Zero takes the default, 256 MiB, which is
	// four checks at once and a queue for the rest; a check that finds both
	// full is refused rather than run. Raise it on a busy server with many
	// distinct accounts and the memory to spare, lower it on a small box.
	KDFMemoryBudget int64
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:             "1080",
		ListenIP:         "0.0.0.0",
		RequireAuth:      true,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		HandshakeTimeout: DefaultHandshakeTimeout,
		DialTimeout:      DefaultDialTimeout,
		FrameTimeout:     DefaultFrameTimeout,
		QuotaGrace:       DefaultQuotaGrace,
		MaxConnections:   10000,
		Fail2BanRetries:  5,
		Fail2BanTime:     5 * time.Minute,
		ObfsReplayWindow: obfs.DefaultSaltHistory,
	}
}

// ValidateConfig checks that the configuration is valid before starting the server.
func ValidateConfig(cfg Config) error {
	// The client whitelist is read here so that a list that cannot be read
	// stops NewServer, rather than being read leniently at Start and leaving
	// an open server behind. One parser, one verdict; see parseWhitelist.
	if _, err := parseWhitelist(cfg.AllowedIPs); err != nil {
		return err
	}
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
		if cfg.ObfsKeepaliveMin < 0 || cfg.ObfsKeepaliveMax < 0 {
			return fmt.Errorf("KEEPALIVE_MIN and KEEPALIVE_MAX must not be negative")
		}
		if cfg.ObfsKeepaliveMin > 0 && cfg.ObfsKeepaliveMax < cfg.ObfsKeepaliveMin {
			// A maximum below the minimum would collapse the draw to a
			// constant, which is the one shape the interval exists to avoid.
			return fmt.Errorf("KEEPALIVE_MAX (%v) must be at least KEEPALIVE_MIN (%v)",
				cfg.ObfsKeepaliveMax, cfg.ObfsKeepaliveMin)
		}
	}
	if cfg.WSEnabled {
		if cfg.WSCertFile == "" || cfg.WSKeyFile == "" {
			return fmt.Errorf("WS_CERT_FILE and WS_KEY_FILE are required when WS_ENABLED is true")
		}
		if cfg.WSMinFrame < 0 || cfg.WSMaxFrame < 0 {
			return fmt.Errorf("WS_MIN_FRAME and WS_MAX_FRAME must be >= 0")
		}
		if cfg.WSMaxFrame > 0 && cfg.WSMinFrame > cfg.WSMaxFrame {
			return fmt.Errorf("WS_MIN_FRAME (%d) must not exceed WS_MAX_FRAME (%d)", cfg.WSMinFrame, cfg.WSMaxFrame)
		}
		// An empty path is legal here and becomes DefaultWSPath below; every
		// other bad path is rejected now, with a sentence about WS_PATH,
		// rather than later as a panic from net/http about mux patterns.
		if cfg.WSPath != "" {
			if err := tlsdecoy.ValidatePath(cfg.WSPath); err != nil {
				return fmt.Errorf("WS_PATH is not usable: %w", err)
			}
		}
		// A decoy that cannot be reached is worse than no decoy: the
		// deployment would serve a gateway error to every visitor and
		// look like a broken host. The URL is checked here, at startup.
		if _, err := tlsdecoy.ValidateUpstream(cfg.WSDecoyUpstream); err != nil {
			return fmt.Errorf("WS_DECOY_UPSTREAM is not usable: %w", err)
		}
	}
	// An advice that sends clients to a transport this server does not run
	// would have every client try it, fail, and come back - a migration to
	// nowhere. Refused at startup, with the variable named.
	if err := validateAdvice(cfg); err != nil {
		return err
	}
	if err := validateTelemetry(cfg.Telemetry); err != nil {
		return err
	}
	return nil
}

// validateTelemetry reports the first instrument a Telemetry is missing.
//
// Every field is an interface, so a struct literal with two of them filled in
// compiles exactly as well as the result of InitTelemetry, starts the server
// and then panics on the first connection that touches the missing one. That
// is a configuration mistake with a runtime address, which is the worst place
// to read it; here it is a sentence naming the field.
func validateTelemetry(t *Telemetry) error {
	if t == nil {
		// Telemetry is optional. Every call site checks for a nil Telemetry.
		return nil
	}
	v := reflect.ValueOf(*t)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Interface, reflect.Pointer, reflect.Func, reflect.Map, reflect.Slice:
			if f.IsNil() {
				return fmt.Errorf("telemetry is incomplete: Telemetry.%s is not set; build it with InitTelemetry instead of a struct literal",
					v.Type().Field(i).Name)
			}
		}
	}
	return nil
}

// Transport names used as metric labels and in the startup summary.
const (
	TransportPlain = "plain"
	TransportObfs  = "obfs"
	TransportWS    = "ws"
)

// Default frame shaping parameters for the WebSocket transport. They are the
// same numbers the client defaults to, so a server started with WS_ENABLED and
// nothing else still talks to a client started the same way. They need no
// agreement between the two ends either: shaping is a property of what a side
// sends, and the peer reassembles a byte stream regardless.
//
// The minimum is 256 rather than 512 because it is the lower end of the band
// the shaper cuts towards, and a band that starts at 512 leaves an obfuscated
// frame of 1400-1700 bytes only one way to be cut - in half - which puts the
// inner length back on the wire divided by two. See pkg/transport/ws/shaped.go.
const (
	DefaultWSPath     = "/ws"
	DefaultWSMinFrame = ws.DefaultMinFrame
	DefaultWSMaxFrame = ws.DefaultMaxFrame
)

// DefaultHandshakeTimeout is the budget for the whole SOCKS5 setup. It has to
// cover password hashing, so it is not one second; it has to make a stalled
// handshake cheap, so it is not thirty.
const DefaultHandshakeTimeout = 15 * time.Second

// DefaultDialTimeout bounds one connection attempt to the destination. It is
// short on purpose: a dial that has not answered in ten seconds is the client
// waiting in the Dialing state, and the bug report is a pile of exactly those.
const DefaultDialTimeout = 10 * time.Second

// DefaultFrameTimeout is how long an obfuscation frame may stay incomplete
// once its header has arrived. A header without its body is a stalled reader,
// and it holds whether the connection is a stream or a silent tunnel.
const DefaultFrameTimeout = 10 * time.Second

// DefaultQuotaGrace is how long a session drains after its account runs out.
// It is the window the in-flight answer of a spent quota gets to arrive in.
const DefaultQuotaGrace = 5 * time.Second

// applyWSDefaults fills in the WebSocket settings that must not be empty.
// An empty WSPath in particular is not a neutral value: net/http.ServeMux
// panics on an empty pattern, so a server configured only with WS_ENABLED
// would die at startup.
func applyWSDefaults(cfg *Config) {
	if !cfg.WSEnabled {
		return
	}
	if cfg.WSPath == "" {
		cfg.WSPath = DefaultWSPath
	}
	if cfg.WSMinFrame == 0 {
		cfg.WSMinFrame = DefaultWSMinFrame
	}
	if cfg.WSMaxFrame == 0 {
		cfg.WSMaxFrame = DefaultWSMaxFrame
	}
}
