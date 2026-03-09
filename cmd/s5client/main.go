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
	"github.com/mazixs/S5Core/internal/socks5"
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

	// Step 1-2: SOCKS5 handshake (read request)
	connectReq, cmd, destFQDN, err := socks5Handshake(clientConn)
	if err != nil {
		slog.Error("SOCKS5 handshake failed", "error", err)
		return
	}

	// Step 3: Check domain routing (only for CONNECT)
	if cmd == socks5.ConnectCommand && !checkRouting(clientConn, destFQDN, routePatterns) {
		return
	}

	// For UDP Associate, we need to rewrite the command byte to our custom UDPTunnelCommand (0x83)
	// before sending it through the tunnel, so the server knows to multiplex it over TCP.
	wireReq := make([]byte, len(connectReq))
	copy(wireReq, connectReq)
	if cmd == socks5.AssociateCommand {
		wireReq[1] = socks5.UDPTunnelCommand
	}

	// Step 4-5: Establish obfs tunnel and forward SOCKS5 request
	obfsConn, err := dialObfsTunnel(cfg, wireReq)
	if err != nil {
		slog.Error("Tunnel setup failed", "error", err, "server", cfg.ServerAddr)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return
	}
	defer obfsConn.Close()

	// Handle based on command
	if cmd == socks5.AssociateCommand {
		handleUDPAssociate(clientConn, obfsConn)
		return
	}

	// Handle normal CONNECT
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
	slog.Info("TCP Tunnel established", "domain", destFQDN, "server", cfg.ServerAddr)

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

// socks5Handshake reads the SOCKS5 greeting and request from the client.
// Returns the raw request bytes, the command type, parsed destination FQDN, and any error.
func socks5Handshake(clientConn net.Conn) (req []byte, cmd byte, destFQDN string, err error) {
	// Read SOCKS5 greeting exactly to avoid relying on packet boundaries.
	if err := readSocks5Greeting(clientConn); err != nil {
		return nil, 0, "", fmt.Errorf("invalid SOCKS5 greeting: %w", err)
	}

	// Respond: no auth required locally
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, 0, "", fmt.Errorf("failed to send greeting response: %w", err)
	}

	// Read SOCKS5 request exactly to avoid partial-read stalls and truncation.
	req, cmd, destFQDN, err = readSocks5Request(clientConn)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid SOCKS5 request: %w", err)
	}

	if cmd != socks5.ConnectCommand && cmd != socks5.AssociateCommand {
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return nil, 0, "", fmt.Errorf("unsupported command: %d", cmd)
	}

	return req, cmd, destFQDN, nil
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

	// Send SOCKS5 greeting with supported auth methods.
	// In no-auth mode we can safely pipeline CONNECT behind the greeting
	// and save one WAN RTT.
	if cfg.ProxyUser != "" {
		// Offer both no-auth and user/pass to preserve compatibility with
		// existing server configs.
		if _, err := obfsConn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			obfsConn.Close()
			return nil, fmt.Errorf("failed to send greeting: %w", err)
		}
	} else {
		pipelined := make([]byte, 0, 3+len(connectReq))
		pipelined = append(pipelined, 0x05, 0x01, 0x00)
		pipelined = append(pipelined, connectReq...)
		if _, err := obfsConn.Write(pipelined); err != nil {
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
		if cfg.ProxyUser == "" {
			return obfsConn, nil
		}
		// No auth required — proceed
	case 0x02:
		// User/pass auth (RFC 1929)
		if cfg.ProxyUser == "" {
			obfsConn.Close()
			return nil, fmt.Errorf("server requires auth but PROXY_USER not set")
		}
		authReq := buildUserPassAuthPacket(cfg.ProxyUser, cfg.ProxyPass)
		pipelined := make([]byte, 0, len(authReq)+len(connectReq))
		pipelined = append(pipelined, authReq...)
		pipelined = append(pipelined, connectReq...)
		if _, err := obfsConn.Write(pipelined); err != nil {
			obfsConn.Close()
			return nil, fmt.Errorf("failed to send auth: %w", err)
		}
		if err := readUserPassAuthResponse(obfsConn); err != nil {
			obfsConn.Close()
			return nil, err
		}
		return obfsConn, nil
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

func buildUserPassAuthPacket(user, pass string) []byte {
	// Build auth request: [version(1)] [ulen(1)] [user] [plen(1)] [pass]
	pkt := make([]byte, 0, 3+len(user)+len(pass))
	pkt = append(pkt, 0x01)            // auth sub-negotiation version
	pkt = append(pkt, byte(len(user))) // username length
	pkt = append(pkt, []byte(user)...) // username
	pkt = append(pkt, byte(len(pass))) // password length
	pkt = append(pkt, []byte(pass)...) // password
	return pkt
}

func readUserPassAuthResponse(conn io.Reader) error {
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("authentication failed (status: 0x%02x)", resp[1])
	}

	return nil
}

func readSocks5Greeting(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	methodsLen := int(header[1])
	if methodsLen == 0 {
		return fmt.Errorf("no auth methods provided")
	}

	methods := make([]byte, methodsLen)
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	return nil
}

func readSocks5Request(r io.Reader) ([]byte, byte, string, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, "", err
	}
	if header[0] != 0x05 {
		return nil, 0, "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	req := make([]byte, 0, 4+1+255+2)
	req = append(req, header[:]...)

	var addrPart []byte
	var destFQDN string
	switch header[3] {
	case 0x01:
		addrPart = make([]byte, 4)
		if _, err := io.ReadFull(r, addrPart); err != nil {
			return nil, 0, "", err
		}
	case 0x04:
		addrPart = make([]byte, 16)
		if _, err := io.ReadFull(r, addrPart); err != nil {
			return nil, 0, "", err
		}
	case 0x03:
		var domainLen [1]byte
		if _, err := io.ReadFull(r, domainLen[:]); err != nil {
			return nil, 0, "", err
		}
		addrPart = append(addrPart, domainLen[0])
		domain := make([]byte, int(domainLen[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, 0, "", err
		}
		addrPart = append(addrPart, domain...)
		destFQDN = string(domain)
	default:
		return nil, 0, "", fmt.Errorf("unsupported address type: %d", header[3])
	}
	req = append(req, addrPart...)

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, 0, "", err
	}
	req = append(req, port[:]...)

	return req, header[1], destFQDN, nil
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
