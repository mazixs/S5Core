package s5server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/armon/go-socks5"
	"github.com/mazixs/S5Core/internal/s5core"
	"golang.org/x/net/netutil"
)

// Server represents a controllable SOCKS5 server instance.
type Server struct {
	cfg        Config
	socks5     *socks5.Server
	listener   *serverListener
	tcpListen  net.Listener
	credStore  *fail2banStore
	logger     *slog.Logger
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewServer initializes a new SOCKS5 server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	socks5conf := &socks5.Config{
		Logger: cfg.Logger,
	}

	var credStore *fail2banStore

	if cfg.RequireAuth {
		var store socks5.CredentialStore
		store = socks5.StaticCredentials{}

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

	srv, err := socks5.New(socks5conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 server: %w", err)
	}

	return &Server{
		cfg:       cfg,
		socks5:    srv,
		logger:    logger,
		credStore: credStore,
	}, nil
}

// AddUser adds a new user for authentication
func (s *Server) AddUser(username, password string) error {
	if s.credStore == nil {
		return fmt.Errorf("authentication is not enabled")
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

// RemoveUser removes a user from authentication
func (s *Server) RemoveUser(username string) error {
	if s.credStore == nil {
		return fmt.Errorf("authentication is not enabled")
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
	go func() {
		if err := s.socks5.Serve(s.listener); err != nil {
			errCh <- err
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
		}

		s.logger.Info("Obfuscation ENABLED on separate port",
			"obfs_port", s.cfg.ObfsPort,
			"max_padding", s.cfg.ObfsMaxPadding,
			"mtu", s.cfg.ObfsMTU,
			"psk_length", len(s.cfg.ObfsPSK),
		)

		go func() {
			if err := s.socks5.Serve(ol); err != nil {
				errCh <- err
			}
		}()
	} else {
		s.logger.Warn("Obfuscation DISABLED — only plain SOCKS5 is available")
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
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
