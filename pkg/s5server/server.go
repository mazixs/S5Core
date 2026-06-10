package s5server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/s5core"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/transport/tlsdecoy"
	"golang.org/x/net/netutil"
)

// Server represents a controllable SOCKS5 server instance.
type Server struct {
	cfg        Config
	socks5     *socks5.Server
	listener   *serverListener
	obfsListen net.Listener
	obfsL      *obfsListener
	wsListen   net.Listener
	wsL        *wsListener
	tcpListen  net.Listener
	credStore  *fail2banStore
	userStore  *userstore.Store
	logger     *slog.Logger
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
}

// NewServer initializes a new SOCKS5 server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	socks5conf := &socks5.Config{
		Logger: cfg.Logger,
	}

	var credStore *fail2banStore
	var uStore *userstore.Store

	if cfg.RequireAuth {
		var store socks5.CredentialStore

		// If UsersFile is configured, use it as the primary credential source
		if cfg.UsersFile != "" {
			uStore = userstore.NewStore(logger)
			if err := uStore.LoadFromFile(cfg.UsersFile); err != nil {
				return nil, fmt.Errorf("failed to load users file: %w", err)
			}
			store = userstore.NewCredentialAdapter(uStore)

			// Wire per-user traffic callback (for UDP handlers)
			socks5conf.TrafficCallback = func(username string, bytes int64) {
				uStore.AddTraffic(username, bytes)
			}
			// Wire lock-free traffic counter (for TCP hot path)
			socks5conf.TrafficCounter = uStore.TrafficCounterFor
		} else {
			store = socks5.StaticCredentials{}
		}

		if cfg.Fail2BanRetries > 0 {
			credStore = newFail2banStore(store, cfg.Fail2BanRetries, cfg.Fail2BanTime, cfg.Telemetry)
			store = credStore
		}

		cator := socks5.UserPassAuthenticator{Credentials: store}
		socks5conf.AuthMethods = []socks5.Authenticator{cator}
	} else {
		logger.Warn("Running the proxy server without authentication is NOT recommended")
	}

	if cfg.AllowedDestFqdn != "" {
		ruleset, err := s5core.PermitDestAddrPattern(cfg.AllowedDestFqdn)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOWED_DEST_FQDN pattern: %w", err)
		}
		socks5conf.Rules = ruleset
	}

	if cfg.Telemetry != nil {
		socks5conf.BytesAddIn = func(n int64) {
			cfg.Telemetry.BytesIn.Add(context.Background(), n)
		}
		socks5conf.BytesAddOut = func(n int64) {
			cfg.Telemetry.BytesOut.Add(context.Background(), n)
		}
	}

	srv, err := socks5.New(socks5conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 server: %w", err)
	}

	return &Server{
		cfg:       cfg,
		socks5:    srv,
		logger:    logger,
		credStore: credStore,
		userStore: uStore,
	}, nil
}

// ReloadUsers reloads the user store from the configured file.
// Traffic counters are preserved across reloads.
func (s *Server) ReloadUsers() error {
	if s.userStore == nil {
		return fmt.Errorf("user store is not configured")
	}
	return s.userStore.Reload(s.cfg.UsersFile)
}

// AddUser adds a new user for authentication.
// When userstore (USERS_FILE) is active the password is hashed with Argon2id
// and the user is persisted in-memory.
func (s *Server) AddUser(username, password string) error {
	if s.credStore == nil {
		return fmt.Errorf("authentication is not enabled")
	}

	if s.userStore != nil {
		return s.userStore.AddUser(username, password)
	}

	s.credStore.mu.Lock()
	defer s.credStore.mu.Unlock()

	staticCreds, ok := s.credStore.store.(socks5.StaticCredentials)
	if !ok {
		return fmt.Errorf("underlying credential store is not modifiable")
	}

	staticCreds[username] = password
	return nil
}

// RemoveUser removes a user from authentication.
func (s *Server) RemoveUser(username string) error {
	if s.credStore == nil {
		return fmt.Errorf("authentication is not enabled")
	}

	if s.userStore != nil {
		return s.userStore.RemoveUser(username)
	}

	s.credStore.mu.Lock()
	defer s.credStore.mu.Unlock()

	staticCreds, ok := s.credStore.store.(socks5.StaticCredentials)
	if !ok {
		return fmt.Errorf("underlying credential store is not modifiable")
	}

	delete(staticCreds, username)
	return nil
}

// UpdateWhitelist updates allowed IPs on the fly
func (s *Server) UpdateWhitelist(ips []string) error {
	var whitelist []net.IP
	if len(ips) > 0 {
		whitelist = make([]net.IP, 0, len(ips))
		for _, ipStr := range ips {
			parsedIP := net.ParseIP(ipStr)
			if parsedIP == nil {
				return fmt.Errorf("invalid IP in whitelist: %s", ipStr)
			}
			whitelist = append(whitelist, parsedIP)
		}
	}

	if s.listener != nil {
		s.listener.setWhitelist(whitelist)
	}
	return nil
}

// UpdateTimeouts updates read/write timeouts on the fly.
func (s *Server) UpdateTimeouts(read, write time.Duration) {
	if s.listener != nil {
		s.listener.setTimeouts(read, write)
	}
	if s.obfsL != nil {
		s.obfsL.setTimeouts(read, write)
	}
}

// Start begins listening and serving traffic. It blocks until stopped.
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancelFunc = context.WithCancel(ctx)

	listenAddr := net.JoinHostPort(s.cfg.ListenIP, s.cfg.Port)
	if s.cfg.ListenIP == "" {
		listenAddr = ":" + s.cfg.Port
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	s.tcpListen = l

	if s.cfg.MaxConnections > 0 {
		l = netutil.LimitListener(l, s.cfg.MaxConnections)
		s.logger.Info("Connection limit set", "max_connections", s.cfg.MaxConnections)
	}

	var initialWhitelist []net.IP
	if len(s.cfg.AllowedIPs) > 0 {
		for _, ipStr := range s.cfg.AllowedIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				initialWhitelist = append(initialWhitelist, ip)
			}
		}
	}

	s.listener = &serverListener{
		Listener:     l,
		whitelist:    initialWhitelist,
		readTimeout:  s.cfg.ReadTimeout,
		writeTimeout: s.cfg.WriteTimeout,
	}

	s.logger.Info("Start listening proxy service (plain SOCKS5)", "address", listenAddr)

	errCh := make(chan error, 2)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.socks5.ServeContext(s.ctx, s.listener); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()

	// Start obfuscated listener on a separate port if enabled
	if s.cfg.ObfsEnabled && s.cfg.ObfsPort != "" {
		obfsAddr := net.JoinHostPort(s.cfg.ListenIP, s.cfg.ObfsPort)
		if s.cfg.ListenIP == "" {
			obfsAddr = ":" + s.cfg.ObfsPort
		}

		obfsL, err := net.Listen("tcp", obfsAddr)
		if err != nil {
			return fmt.Errorf("failed to listen obfs on %s: %w", obfsAddr, err)
		}
		s.obfsListen = obfsL

		obfsServerListener := &serverListener{
			Listener:     obfsL,
			whitelist:    initialWhitelist,
			readTimeout:  s.cfg.ReadTimeout,
			writeTimeout: s.cfg.WriteTimeout,
		}

		ol := &obfsListener{
			serverListener: obfsServerListener,
			psk:            []byte(s.cfg.ObfsPSK),
			maxPadding:     s.cfg.ObfsMaxPadding,
			mtu:            s.cfg.ObfsMTU,
			replayWindow:   s.cfg.ObfsReplayWindow,
		}
		s.obfsL = ol

		s.logger.Info("Obfuscation ENABLED on separate port",
			"obfs_port", s.cfg.ObfsPort,
			"max_padding", s.cfg.ObfsMaxPadding,
			"mtu", s.cfg.ObfsMTU,
			"psk_length", len(s.cfg.ObfsPSK),
		)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.socks5.ServeContext(s.ctx, ol); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	} else {
		s.logger.Warn("Obfuscation DISABLED — only plain SOCKS5 is available")
	}

	// Start WebSocket-over-TLS listener if enabled
	if s.cfg.WSEnabled {
		wsAddr := s.cfg.WSAddr
		if wsAddr == "" {
			wsAddr = net.JoinHostPort(s.cfg.ListenIP, "443")
			if s.cfg.ListenIP == "" {
				wsAddr = ":443"
			}
		}

		tdl, err := tlsdecoy.NewListener(tlsdecoy.Config{
			Addr:         wsAddr,
			CertFile:     s.cfg.WSCertFile,
			KeyFile:      s.cfg.WSKeyFile,
			WSPath:       s.cfg.WSPath,
			Subprotocols: []string{s.cfg.WSSubprotocol},
		})
		if err != nil {
			return fmt.Errorf("failed to start WS listener on %s: %w", wsAddr, err)
		}

		wl := &wsListener{
			Listener:     tdl,
			psk:          []byte(s.cfg.ObfsPSK),
			maxPadding:   s.cfg.ObfsMaxPadding,
			mtu:          s.cfg.ObfsMTU,
			replayWindow: s.cfg.ObfsReplayWindow,
			wsMinFrame:   s.cfg.WSMinFrame,
			wsMaxFrame:   s.cfg.WSMaxFrame,
			wsMaxJitter:  s.cfg.WSMaxJitter,
		}
		s.wsListen = tdl
		s.wsL = wl

		s.logger.Info("WebSocket stealth transport ENABLED",
			"ws_addr", wsAddr,
			"ws_path", s.cfg.WSPath,
		)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.socks5.ServeContext(s.ctx, wl); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}

	// Start periodic traffic flush if user store is configured
	if s.userStore != nil {
		flushInterval := s.cfg.TrafficFlushInterval
		if flushInterval <= 0 {
			flushInterval = 60 * time.Second
		}
		s.userStore.StartPeriodicFlush(s.cfg.UsersFile, flushInterval)
	}

	select {
	case <-s.ctx.Done():
		s.logger.Info("Server context canceled, shutting down...")
		return s.listener.Close()
	case err := <-errCh:
		return err
	}
}

// Stop gracefully stops the proxy server.
func (s *Server) Stop() error {
	if s.userStore != nil {
		s.userStore.StopPeriodicFlush()
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.obfsListen != nil {
		_ = s.obfsListen.Close()
	}
	if s.wsListen != nil {
		_ = s.wsListen.Close()
	}
	s.wg.Wait()
	return nil
}

// WSAddr returns the network address of the WebSocket stealth listener,
// or empty string if WS is not enabled.
func (s *Server) WSAddr() string {
	if s.wsListen != nil {
		return s.wsListen.Addr().String()
	}
	return ""
}
