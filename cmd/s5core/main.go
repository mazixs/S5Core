package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/signals"
	"github.com/mazixs/S5Core/pkg/s5server"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

type params struct {
	User             string        `env:"PROXY_USER" envDefault:""`
	Password         string        `env:"PROXY_PASSWORD" envDefault:""`
	Port             string        `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn  string        `env:"ALLOWED_DEST_FQDN" envDefault:""`
	AllowedIPs       []string      `env:"ALLOWED_IPS" envSeparator:"," envDefault:""`
	ListenIP         string        `env:"PROXY_LISTEN_IP" envDefault:"0.0.0.0"`
	RequireAuth      bool          `env:"REQUIRE_AUTH" envDefault:"true"`
	ReadTimeout      time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout     time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	HandshakeTimeout time.Duration `env:"HANDSHAKE_TIMEOUT" envDefault:"15s"`
	DialTimeout      time.Duration `env:"DIAL_TIMEOUT" envDefault:"10s"`
	FrameTimeout     time.Duration `env:"FRAME_TIMEOUT" envDefault:"10s"`
	QuotaGrace       time.Duration `env:"QUOTA_GRACE" envDefault:"5s"`
	MaxConnections   int           `env:"MAX_CONNECTIONS" envDefault:"10000"`
	MetricsPort      string        `env:"METRICS_PORT" envDefault:"8080"`
	MetricsBindAddr  string        `env:"METRICS_BIND_ADDR" envDefault:"127.0.0.1"`
	Fail2BanRetries  int           `env:"FAIL2BAN_RETRIES" envDefault:"5"`
	Fail2BanTime     time.Duration `env:"FAIL2BAN_TIME" envDefault:"5m"`
	ObfsEnabled      bool          `env:"OBFS_ENABLED" envDefault:"false"`
	ObfsPort         string        `env:"OBFS_PORT" envDefault:"1443"`
	ObfsPSK          string        `env:"OBFS_PSK" envDefault:""`
	ObfsMaxPadding   int           `env:"OBFS_MAX_PADDING" envDefault:"256"`
	ObfsMTU          int           `env:"OBFS_MTU" envDefault:"1400"`
	ObfsReplayWindow int           `env:"OBFS_REPLAY_WINDOW" envDefault:"10000"`
	// ObfsNodeID binds this node's keys to this node. A prologue minted for
	// another node does not authenticate here, which is what lets each node
	// keep its own replay history instead of sharing one (plan task Ф5-4).
	// Empty means unbound, and every node of a fleet accepts every client.
	ObfsNodeID string `env:"OBFS_NODE_ID" envDefault:""`
	// ObfsAcceptNodeIDs are additional node identifiers this server accepts
	// besides its own, for the window in which clients are being moved from
	// one to another. Each costs one HMAC per connection.
	ObfsAcceptNodeIDs []string `env:"OBFS_ACCEPT_NODE_IDS" envSeparator:","`
	// ObfsRequireMemberKey closes the shared account: only clients holding
	// a per-user tunnel key from USERS_FILE may connect. Turn it on at the
	// end of a migration, once every client in the field has a key.
	ObfsRequireMemberKey bool `env:"OBFS_REQUIRE_MEMBER_KEY" envDefault:"false"`
	// Off by default: the client holds the path open, and a server sending
	// keepalives to every idle connection adds traffic that buys nothing.
	// Turn it on for deployments whose clients are not s5client.
	KeepaliveMin time.Duration `env:"KEEPALIVE_MIN" envDefault:"0s"`
	KeepaliveMax time.Duration `env:"KEEPALIVE_MAX" envDefault:"0s"`
	// WebSocket-over-TLS stealth transport. Until these were read here, about
	// 700 lines of working transport code were reachable only from the SDK,
	// while README and .env.example documented them as if the binary had them.
	WSEnabled  bool   `env:"WS_ENABLED" envDefault:"false"`
	WSAddr     string `env:"WS_ADDR" envDefault:""`
	WSCertFile string `env:"WS_CERT_FILE" envDefault:""`
	WSKeyFile  string `env:"WS_KEY_FILE" envDefault:""`
	WSPath     string `env:"WS_PATH" envDefault:"/ws"`
	// WSDecoyUpstream turns the decoy into a reverse proxy to a real site.
	WSDecoyUpstream string `env:"WS_DECOY_UPSTREAM"`
	// TransportAdvice is sent to every client inside its tunnel: the
	// transport to use next and the traffic shape to adopt (plan task
	// Ф5-7). Reloaded on SIGHUP, so moving the fleet is one variable and
	// one signal, not a release.
	TransportAdvice string `env:"TRANSPORT_ADVICE"`
	// TransportAdviceFile is where the advice is read from when the
	// operator needs to change it without restarting: the environment of a
	// running process cannot be edited from outside it. Set, it wins over
	// TRANSPORT_ADVICE, the way LOG_LEVEL_FILE wins over LOG_LEVEL. See
	// advice_file.go.
	TransportAdviceFile string `env:"TRANSPORT_ADVICE_FILE"`
	WSSubprotocol       string `env:"WS_SUBPROTOCOL" envDefault:""`
	WSMinFrame          int    `env:"WS_MIN_FRAME" envDefault:"256"`
	WSMaxFrame          int    `env:"WS_MAX_FRAME" envDefault:"4096"`
	WSMaxJitterMs       int    `env:"WS_MAX_JITTER_MS" envDefault:"0"`

	// TLSFingerprint is a client-side setting. The server reads it only to say
	// out loud that it does nothing here, because setting it on the server and
	// believing the traffic is now shaped is a plausible and costly mistake.
	TLSFingerprint string `env:"TLS_FINGERPRINT" envDefault:""`

	UsersFile    string        `env:"USERS_FILE" envDefault:""`
	TrafficFlush time.Duration `env:"TRAFFIC_FLUSH_INTERVAL" envDefault:"60s"`
	// KDFMemoryBudgetMB is the memory concurrent password checks may use.
	// Zero is the library default (256 MiB); a negative value removes the
	// bound and is for embedders that have their own.
	KDFMemoryBudgetMB int    `env:"KDF_MEMORY_BUDGET_MB" envDefault:"0"`
	LogLevel          string `env:"LOG_LEVEL" envDefault:"info"`
}

// loadConfig is the binary's whole configuration path: the environment, the
// aliases kept for older deployments, and the advice, which has a source
// outside the environment because it is the one setting meant to change on a
// running process (audit finding F19, advice_file.go).
func loadConfig() (params, error) {
	var cfg params
	if err := env.Parse(&cfg); err != nil {
		return cfg, err
	}
	applyEnvAliases(&cfg)
	// Same rule as a typo in TRANSPORT_ADVICE: a server that starts and
	// quietly advises nothing leaves the operator believing the fleet is
	// moving.
	if err := resolveTransportAdvice(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func main() {
	logger, levelErr := logging.Setup(os.Stdout)
	if levelErr != nil {
		slog.Warn("Invalid LOG_LEVEL, falling back to info", "error", levelErr)
	}

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("Failed to read the configuration", "error", err)
		os.Exit(1)
	}

	// Initialize OpenTelemetry Prometheus Exporter
	telemetry, err := setupTelemetry()
	if err != nil {
		slog.Error("Failed to initialize telemetry", "error", err)
		os.Exit(1)
	}

	srv, err := setupServer(cfg, telemetry, logger)
	if err != nil {
		slog.Error("Server configuration failed", "error", err)
		os.Exit(1)
	}

	// Set up graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), signals.Terminate...)
	defer stop()

	// Set up SIGHUP context for configuration hot reloading
	setupHotReload(ctx, srv)

	// SIGUSR1 переключает debug без какой-либо предварительной настройки:
	// окружение работающего процесса извне не изменить, а инцидент случается
	// на сервере, который уже запущен.
	setupLogLevelToggle(ctx)

	// Start metrics server (Legacy Prometheus endpoint)
	if cfg.MetricsPort != "" {
		go startMetricsServer(ctx, cfg.MetricsBindAddr, cfg.MetricsPort)
	}

	startErr := srv.Start(ctx)

	// Stop is what flushes the traffic counters to USERS_FILE and waits for
	// the connection handlers. Without this call the last interval of every
	// user's traffic - up to TRAFFIC_FLUSH_INTERVAL of it - was lost on every
	// restart, and the process exited with its handlers still running.
	if err := srv.Stop(); err != nil {
		slog.Error("Shutdown reported an error", "error", err)
	}

	if startErr != nil && !errors.Is(startErr, context.Canceled) {
		slog.Error("Server stopped with error", "error", startErr)
		os.Exit(1)
	}

	slog.Info("Server stopped cleanly")
}

// applyEnvAliases accepts the names the other binary uses for the same thing.
//
// The client authenticates with PROXY_USER and PROXY_PASS; the server reads
// PROXY_USER and PROXY_PASSWORD. The two files get copied between machines, and
// the result was a server that refused to start with a message listing the name
// the operator thought they had set. The alias is accepted and reported, rather
// than renamed outright: a deployment that already sets PROXY_PASSWORD keeps
// working, and one that sets PROXY_PASS learns the canonical name from its own
// log instead of from this file.
func applyEnvAliases(cfg *params) {
	if cfg.Password != "" {
		return
	}
	alias, ok := os.LookupEnv("PROXY_PASS")
	if !ok || alias == "" {
		return
	}
	cfg.Password = alias
	slog.Warn("PROXY_PASS is the client's name for this setting; the server's name is PROXY_PASSWORD. Using PROXY_PASS for now - rename it.")
}

func setupTelemetry() (*s5server.Telemetry, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize prometheus exporter: %w", err)
	}
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	return s5server.InitTelemetry(provider)
}

func setupServer(cfg params, telemetry *s5server.Telemetry, logger *slog.Logger) (*s5server.Server, error) {
	serverCfg := s5server.Config{
		Logger:               logger,
		Port:                 cfg.Port,
		ListenIP:             cfg.ListenIP,
		RequireAuth:          cfg.RequireAuth,
		AllowedDestFqdn:      cfg.AllowedDestFqdn,
		AllowedIPs:           cfg.AllowedIPs,
		ReadTimeout:          cfg.ReadTimeout,
		WriteTimeout:         cfg.WriteTimeout,
		HandshakeTimeout:     cfg.HandshakeTimeout,
		DialTimeout:          cfg.DialTimeout,
		FrameTimeout:         cfg.FrameTimeout,
		QuotaGrace:           cfg.QuotaGrace,
		MaxConnections:       cfg.MaxConnections,
		Fail2BanRetries:      cfg.Fail2BanRetries,
		Fail2BanTime:         cfg.Fail2BanTime,
		Telemetry:            telemetry,
		ObfsEnabled:          cfg.ObfsEnabled,
		ObfsPort:             cfg.ObfsPort,
		ObfsPSK:              cfg.ObfsPSK,
		ObfsMaxPadding:       cfg.ObfsMaxPadding,
		ObfsMTU:              cfg.ObfsMTU,
		ObfsKeepaliveMin:     cfg.KeepaliveMin,
		ObfsKeepaliveMax:     cfg.KeepaliveMax,
		ObfsReplayWindow:     cfg.ObfsReplayWindow,
		ObfsNodeID:           cfg.ObfsNodeID,
		ObfsAcceptNodeIDs:    cfg.ObfsAcceptNodeIDs,
		ObfsRequireMemberKey: cfg.ObfsRequireMemberKey,
		WSEnabled:            cfg.WSEnabled,
		WSAddr:               cfg.WSAddr,
		WSCertFile:           cfg.WSCertFile,
		WSKeyFile:            cfg.WSKeyFile,
		WSPath:               cfg.WSPath,
		WSDecoyUpstream:      cfg.WSDecoyUpstream,
		TransportAdvice:      cfg.TransportAdvice,
		WSSubprotocol:        cfg.WSSubprotocol,
		WSMinFrame:           cfg.WSMinFrame,
		WSMaxFrame:           cfg.WSMaxFrame,
		WSMaxJitter:          time.Duration(cfg.WSMaxJitterMs) * time.Millisecond,
		UsersFile:            cfg.UsersFile,
		TrafficFlushInterval: cfg.TrafficFlush,
		KDFMemoryBudget:      int64(cfg.KDFMemoryBudgetMB) << 20,
	}

	if cfg.TLSFingerprint != "" {
		logger.Warn("TLS_FINGERPRINT is a client-side setting and is ignored by the server",
			"tls_fingerprint", cfg.TLSFingerprint)
	}

	srv, err := s5server.NewServer(serverCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server: %w", err)
	}

	if cfg.RequireAuth && cfg.UsersFile == "" {
		// Legacy mode: single user from env
		if cfg.User != "" && cfg.Password != "" {
			if err := srv.AddUser(cfg.User, cfg.Password); err != nil {
				return nil, fmt.Errorf("failed to add proxy user: %w", err)
			}
		} else {
			return nil, fmt.Errorf("REQUIRE_AUTH is true, but neither USERS_FILE nor PROXY_USER/PROXY_PASSWORD are set")
		}
	}

	return srv, nil
}

func setupHotReload(ctx context.Context, srv *s5server.Server) {
	hupCtx := make(chan os.Signal, 1)
	if !signals.Notify(hupCtx, signals.Reload...) {
		// A platform with no reload signal has nothing to listen for, and
		// listening for nothing means listening for everything.
		return
	}
	go func() {
		for {
			select {
			case <-hupCtx:
				slog.Info("SIGHUP received, reloading configuration...")
				var newCfg params
				if err := env.Parse(&newCfg); err != nil {
					slog.Error("Failed to parse env config during reload", "error", err)
					continue
				}

				if err := srv.UpdateWhitelist(newCfg.AllowedIPs); err != nil {
					slog.Error("Failed to update whitelist during reload", "error", err)
				} else {
					slog.Info("Whitelist reloaded successfully")
				}

				srv.UpdateTimeouts(newCfg.ReadTimeout, newCfg.WriteTimeout)
				srv.UpdateHandshakeTimeout(newCfg.HandshakeTimeout)
				srv.UpdateSessionTimeouts(newCfg.DialTimeout, newCfg.FrameTimeout, newCfg.QuotaGrace)
				slog.Info("Timeouts reloaded successfully")

				// The transport advice is the one setting whose whole
				// value is in being changeable without a restart - which is
				// why it is read from its file here and not just re-parsed
				// out of an environment nothing outside this process can
				// change (audit finding F19).
				if err := resolveTransportAdvice(&newCfg); err != nil {
					slog.Error("Failed to read the transport advice during reload, keeping previous", "error", err)
				} else if err := srv.UpdateTransportAdvice(newCfg.TransportAdvice); err != nil {
					slog.Error("Failed to apply TRANSPORT_ADVICE during reload, keeping previous", "error", err)
				} else {
					slog.Info("Transport advice reloaded", "advice", newCfg.TransportAdvice)
				}

				if err := srv.ReloadUsers(); err != nil {
					slog.Error("Failed to reload users during SIGHUP", "error", err)
				} else {
					slog.Info("User store reloaded successfully")
				}

				// Уровень логов меняется на работающем процессе: диагностика
				// протокола включается там, где отказ уже происходит.
				if level, err := logging.SetLevelFromEnv(); err != nil {
					slog.Error("Failed to apply LOG_LEVEL during reload, keeping previous", "error", err, "log_level", level)
				} else {
					slog.Info("Log level applied", "log_level", level)
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

func setupLogLevelToggle(ctx context.Context) {
	usrCh := make(chan os.Signal, 1)
	if !signals.Notify(usrCh, signals.ToggleDebug...) {
		return
	}
	go func() {
		for {
			select {
			case <-usrCh:
				slog.Info("Log level toggled by SIGUSR1", "log_level", logging.ToggleDebug())
			case <-ctx.Done():
				return
			}
		}
	}()
}

// metricsHeaderTimeout bounds how long a client may take to send its request
// headers. Without it a connection that opens and says nothing holds a
// goroutine until the peer gives up, which on a port that exists to report
// the server's health is a way to stop it reporting.
const metricsHeaderTimeout = 5 * time.Second

// newMetricsServer builds the metrics and health endpoint on a mux of its
// own.
//
// It used to be registered on http.DefaultServeMux (plan task Ф6-5), which is
// a global any package can add to: importing net/http/pprof anywhere in the
// binary, directly or through a dependency, would have published the heap and
// goroutine profiles on this port without a line of code saying so. A mux
// declared here serves exactly the two paths declared here.
func newMetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
		// A scrape is a small request and a small answer. These bounds are
		// generous for that and short enough that a stuck client is not a
		// goroutine held indefinitely.
		ReadHeaderTimeout: metricsHeaderTimeout,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func startMetricsServer(ctx context.Context, listenIP, metricsPort string) {
	metricsAddr := net.JoinHostPort(listenIP, metricsPort)
	if listenIP == "" {
		metricsAddr = ":" + metricsPort
	}
	slog.Info("Start listening metrics/health service", "address", metricsAddr)

	metricsServer := newMetricsServer(metricsAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsServer.Shutdown(shutdownCtx)
	}()

	if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Metrics server error", "error", err)
	}
}
