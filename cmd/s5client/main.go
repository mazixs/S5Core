package main

import (
	"fmt"
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
	ProxyUser    string `env:"PROXY_USER" envDefault:""`
	ProxyPass    string `env:"PROXY_PASS" envDefault:""`
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
		"auth", cfg.ProxyUser != "",
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

	// Step 1-2: SOCKS5 handshake
	connectReq, destFQDN, err := socks5Handshake(clientConn)
	if err != nil {
		slog.Error("SOCKS5 handshake failed", "error", err)
		return
	}

	// Step 3: Check domain routing
	if !checkRouting(clientConn, destFQDN, routePatterns) {
		return
	}

	// Step 4-5: Establish obfs tunnel and forward SOCKS5 request
	obfsConn, err := dialObfsTunnel(cfg, connectReq)
	if err != nil {
		slog.Error("Tunnel setup failed", "error", err, "server", cfg.ServerAddr)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return
	}
	defer obfsConn.Close()

	// Read CONNECT response from server
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
		return
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

// socks5Handshake reads the SOCKS5 greeting and CONNECT request from the client.
// Returns the raw CONNECT request bytes, parsed destination FQDN, and any error.
func socks5Handshake(clientConn net.Conn) (connectReq []byte, destFQDN string, err error) {
	buf := make([]byte, 256)

	// Read SOCKS5 greeting
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return nil, "", fmt.Errorf("invalid SOCKS5 greeting: %w", err)
	}

	// Respond: no auth required
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, "", fmt.Errorf("failed to send greeting response: %w", err)
	}

	// Read SOCKS5 CONNECT request
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 {
		return nil, "", fmt.Errorf("invalid SOCKS5 request: %w", err)
	}

	// Parse destination FQDN
	if buf[3] == 0x03 {
		domainLen := int(buf[4])
		if n >= 5+domainLen+2 {
			destFQDN = string(buf[5 : 5+domainLen])
		}
	}

	return buf[:n], destFQDN, nil
}

// checkRouting verifies if the destination domain should be routed through the tunnel.
// Returns true if routing is allowed, false if rejected.
func checkRouting(clientConn net.Conn, destFQDN string, routePatterns []string) bool {
	if len(routePatterns) == 0 || destFQDN == "" {
		return true
	}

	if matchDomain(destFQDN, routePatterns) {
		return true
	}

	slog.Info("Domain not in route list, rejecting", "domain", destFQDN)
	clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	return false
}

// dialObfsTunnel establishes an obfuscated connection to the server and forwards
// the SOCKS5 handshake through the encrypted tunnel.
func dialObfsTunnel(cfg clientParams, connectReq []byte) (net.Conn, error) {
	serverConn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	obfsCfg := obfs.Config{
		PSK:        []byte(cfg.PSK),
		MaxPadding: cfg.MaxPadding,
		MTU:        cfg.MTU,
	}

	obfsConn, err := obfs.NewConn(serverConn, obfsCfg)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("failed to create obfs conn: %w", err)
	}

	// Send SOCKS5 greeting with supported auth methods
	if cfg.ProxyUser != "" {
		// Offer both no-auth and user/pass
		if _, err := obfsConn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			obfsConn.Close()
			return nil, fmt.Errorf("failed to send greeting: %w", err)
		}
	} else {
		if _, err := obfsConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			obfsConn.Close()
			return nil, fmt.Errorf("failed to send greeting: %w", err)
		}
	}

	// Read server greeting response
	var resp [2]byte
	if _, err := io.ReadFull(obfsConn, resp[:]); err != nil {
		obfsConn.Close()
		return nil, fmt.Errorf("failed to read server greeting: %w", err)
	}

	// Handle auth method selected by server
	switch resp[1] {
	case 0x00:
		// No auth required — proceed
	case 0x02:
		// User/pass auth (RFC 1929)
		if cfg.ProxyUser == "" {
			obfsConn.Close()
			return nil, fmt.Errorf("server requires auth but PROXY_USER not set")
		}
		if err := doUserPassAuth(obfsConn, cfg.ProxyUser, cfg.ProxyPass); err != nil {
			obfsConn.Close()
			return nil, err
		}
	case 0xFF:
		obfsConn.Close()
		return nil, fmt.Errorf("server rejected all auth methods")
	default:
		obfsConn.Close()
		return nil, fmt.Errorf("unsupported auth method: 0x%02x", resp[1])
	}

	// Forward CONNECT request
	if _, err := obfsConn.Write(connectReq); err != nil {
		obfsConn.Close()
		return nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	return obfsConn, nil
}

// doUserPassAuth performs RFC 1929 username/password authentication.
func doUserPassAuth(conn net.Conn, user, pass string) error {
	// Build auth request: [version(1)] [ulen(1)] [user] [plen(1)] [pass]
	pkt := make([]byte, 0, 3+len(user)+len(pass))
	pkt = append(pkt, 0x01)            // auth sub-negotiation version
	pkt = append(pkt, byte(len(user))) // username length
	pkt = append(pkt, []byte(user)...) // username
	pkt = append(pkt, byte(len(pass))) // password length
	pkt = append(pkt, []byte(pass)...) // password

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	// Read response: [version(1)] [status(1)]
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("authentication failed (status: 0x%02x)", resp[1])
	}

	return nil
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
