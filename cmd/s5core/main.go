package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/pkg/s5server"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

type params struct {
	User            string        `env:"PROXY_USER" envDefault:""`
	Password        string        `env:"PROXY_PASSWORD" envDefault:""`
	Port            string        `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn string        `env:"ALLOWED_DEST_FQDN" envDefault:""`
	AllowedIPs      []string      `env:"ALLOWED_IPS" envSeparator:"," envDefault:""`
	ListenIP        string        `env:"PROXY_LISTEN_IP" envDefault:"0.0.0.0"`
	RequireAuth     bool          `env:"REQUIRE_AUTH" envDefault:"true"`
	ReadTimeout     time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout    time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	MaxConnections  int           `env:"MAX_CONNECTIONS" envDefault:"10000"`
	MetricsPort     string        `env:"METRICS_PORT" envDefault:"8080"`
	Fail2BanRetries int           `env:"FAIL2BAN_RETRIES" envDefault:"5"`
	Fail2BanTime    time.Duration `env:"FAIL2BAN_TIME" envDefault:"5m"`
	ObfsEnabled     bool          `env:"OBFS_ENABLED" envDefault:"false"`
	ObfsPort        string        `env:"OBFS_PORT" envDefault:"1443"`
	ObfsPSK         string        `env:"OBFS_PSK" envDefault:""`
	ObfsMaxPadding  int           `env:"OBFS_MAX_PADDING" envDefault:"256"`
	ObfsMTU         int           `env:"OBFS_MTU" envDefault:"1400"`
	UsersFile       string        `env:"USERS_FILE" envDefault:""`
	TrafficFlush    time.Duration `env:"TRAFFIC_FLUSH_INTERVAL" envDefault:"60s"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Working with app params
	var cfg params
	if err := env.Parse(&cfg); err != nil {
		slog.Error("Failed to parse env config", "error", err)
		os.Exit(1)
	}

	// Initialize OpenTelemetry Prometheus Exporter
	telemetry, err := setupTelemetry()
	if err != nil {
		slog.Error("Failed to initialize telemetry", "error", err)
		os.Exit(1)
	}

	srv, err := setupServer(cfg, telemetry)
	if err != nil {
		slog.Error("Server configuration failed", "error", err)
		os.Exit(1)
	}

	// Set up graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set up SIGHUP context for configuration hot reloading
	setupHotReload(ctx, srv)

	// Start metrics server (Legacy Prometheus endpoint)
	if cfg.MetricsPort != "" {
		go startMetricsServer(ctx, cfg.ListenIP, cfg.MetricsPort)
	}

	if err := srv.Start(ctx); err != nil {
		slog.Error("Server stopped with error", "error", err)
		os.Exit(1)
	}

	slog.Info("Server stopped cleanly")
}

func setupTelemetry() (*s5server.Telemetry, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize prometheus exporter: %v", err)
	}
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	return s5server.InitTelemetry(provider)
}

func setupServer(cfg params, telemetry *s5server.Telemetry) (*s5server.Server, error) {
	serverCfg := s5server.Config{
		Port:                 cfg.Port,
		ListenIP:             cfg.ListenIP,
		RequireAuth:          cfg.RequireAuth,
		AllowedDestFqdn:      cfg.AllowedDestFqdn,
		AllowedIPs:           cfg.AllowedIPs,
		ReadTimeout:          cfg.ReadTimeout,
		WriteTimeout:         cfg.WriteTimeout,
		MaxConnections:       cfg.MaxConnections,
		Fail2BanRetries:      cfg.Fail2BanRetries,
		Fail2BanTime:         cfg.Fail2BanTime,
		Telemetry:            telemetry,
		ObfsEnabled:          cfg.ObfsEnabled,
		ObfsPort:             cfg.ObfsPort,
		ObfsPSK:              cfg.ObfsPSK,
		ObfsMaxPadding:       cfg.ObfsMaxPadding,
		ObfsMTU:              cfg.ObfsMTU,
		UsersFile:            cfg.UsersFile,
		TrafficFlushInterval: cfg.TrafficFlush,
	}

	srv, err := s5server.NewServer(serverCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server: %v", err)
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
	signal.Notify(hupCtx, syscall.SIGHUP)
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

				if err := srv.ReloadUsers(); err != nil {
					slog.Error("Failed to reload users during SIGHUP", "error", err)
				} else {
					slog.Info("User store reloaded successfully")
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

func startMetricsServer(ctx context.Context, listenIP, metricsPort string) {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	metricsAddr := net.JoinHostPort(listenIP, metricsPort)
	if listenIP == "" {
		metricsAddr = ":" + metricsPort
	}
	slog.Info("Start listening metrics/health service", "address", metricsAddr)

	metricsServer := &http.Server{
		Addr: metricsAddr,
	}

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
