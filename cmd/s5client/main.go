package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/pkg/obfs"
)

type clientParams struct {
	ListenAddr   string `env:"CLIENT_LISTEN_ADDR" envDefault:"127.0.0.1:1080"`
	ServerAddr   string `env:"SERVER_ADDR" envDefault:""`
	PSK          string `env:"OBFS_PSK" envDefault:""`
	MaxPadding   int    `env:"OBFS_MAX_PADDING" envDefault:"256"`
	MTU          int    `env:"OBFS_MTU" envDefault:"1400"`
	RouteDomains string `env:"ROUTE_DOMAINS" envDefault:""`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var cfg clientParams
	if err := env.Parse(&cfg); err != nil {
		slog.Error("Failed to parse env config", "error", err)
		os.Exit(1)
	}

	if cfg.ServerAddr == "" {
		slog.Error("SERVER_ADDR is required")
		os.Exit(1)
	}
	if cfg.PSK == "" || len(cfg.PSK) != 32 {
		slog.Error("OBFS_PSK must be exactly 32 bytes")
		os.Exit(1)
	}

	// Parse domain routing patterns
	var routePatterns []string
	if cfg.RouteDomains != "" {
		for _, d := range strings.Split(cfg.RouteDomains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				routePatterns = append(routePatterns, d)
			}
		}
	}

	slog.Info("S5Client starting",
		"listen", cfg.ListenAddr,
		"server", cfg.ServerAddr,
		"mtu", cfg.MTU,
		"max_padding", cfg.MaxPadding,
		"route_domains", len(routePatterns),
	)

	if len(routePatterns) > 0 {
		slog.Info("Domain routing enabled", "patterns", routePatterns)
	} else {
		slog.Info("Domain routing disabled — all traffic will be tunneled")
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("Failed to listen", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("Shutting down s5client...")
		listener.Close()
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			slog.Error("Accept error", "error", err)
			continue
		}

		go handleClient(clientConn, cfg, routePatterns)
	}
}

func handleClient(clientConn net.Conn, cfg clientParams, routePatterns []string) {
	defer clientConn.Close()

	// Step 1: Read SOCKS5 greeting from client
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		slog.Error("Invalid SOCKS5 greeting", "error", err)
		return
	}

	// Respond: no auth required
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Step 2: Read SOCKS5 CONNECT request
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 {
		slog.Error("Invalid SOCKS5 request", "error", err)
		return
	}

	// Parse destination from SOCKS5 request
	destFQDN := ""
	if buf[3] == 0x03 { // Domain name
		domainLen := int(buf[4])
		if n >= 5+domainLen+2 {
			destFQDN = string(buf[5 : 5+domainLen])
		}
	}

	// Step 3: Check domain routing if patterns are configured
	if len(routePatterns) > 0 && destFQDN != "" {
		if !matchDomain(destFQDN, routePatterns) {
			slog.Info("Domain not in route list, rejecting", "domain", destFQDN)
			// Reply with connection refused (0x02)
			clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	}

	// Step 4: Connect to S5Core server via obfs tunnel
	serverConn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		slog.Error("Failed to connect to server", "error", err, "server", cfg.ServerAddr)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer serverConn.Close()

	obfsCfg := obfs.Config{
		PSK:        []byte(cfg.PSK),
		MaxPadding: cfg.MaxPadding,
		MTU:        cfg.MTU,
	}

	obfsConn, err := obfs.NewConn(serverConn, obfsCfg)
	if err != nil {
		slog.Error("Failed to create obfs conn", "error", err)
		return
	}

	// Step 5: Forward the original SOCKS5 greeting + request through obfs tunnel
	// The server-side S5Core will handle the SOCKS5 protocol after de-obfuscation
	greeting := []byte{0x05, 0x01, 0x00} // SOCKS5, 1 method, no auth
	if _, err := obfsConn.Write(greeting); err != nil {
		slog.Error("Failed to send greeting through tunnel", "error", err)
		return
	}

	// Read server greeting response
	resp := make([]byte, 2)
	if _, err := obfsConn.Read(resp); err != nil {
		slog.Error("Failed to read server greeting", "error", err)
		return
	}

	// Forward the CONNECT request
	if _, err := obfsConn.Write(buf[:n]); err != nil {
		slog.Error("Failed to send CONNECT through tunnel", "error", err)
		return
	}

	// Read CONNECT response
	connectResp := make([]byte, 256)
	rn, err := obfsConn.Read(connectResp)
	if err != nil {
		slog.Error("Failed to read CONNECT response", "error", err)
		return
	}

	// Forward CONNECT response to client
	if _, err := clientConn.Write(connectResp[:rn]); err != nil {
		return
	}

	if rn >= 2 && connectResp[1] != 0x00 {
		return // CONNECT failed on server side
	}

	// Step 6: Bidirectional relay
	slog.Info("Tunnel established", "domain", destFQDN, "server", cfg.ServerAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(obfsConn, clientConn) //nolint:errcheck
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, obfsConn) //nolint:errcheck
	}()

	wg.Wait()
}

// matchDomain checks if FQDN matches any of the routing patterns.
// Supports exact match and wildcard subdomain matching (*.example.com).
func matchDomain(fqdn string, patterns []string) bool {
	fqdn = strings.ToLower(fqdn)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))

		if p == fqdn {
			return true
		}

		// Wildcard match: *.example.com matches sub.example.com and deep.sub.example.com
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(fqdn, suffix) {
				return true
			}
			// Also match the base domain itself
			if fqdn == p[2:] {
				return true
			}
		}
	}
	return false
}

// Ensure binary name in go build output
func init() {
	_ = filepath.Base(os.Args[0])
}
