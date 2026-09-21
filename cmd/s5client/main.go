package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/buildinfo"
	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/signals"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/obfs/legacy"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	"github.com/mazixs/S5Core/pkg/veil"
	"golang.org/x/net/idna"
)

const (
	socks5Ver          = 0x05
	socks5Success      = 0x00
	socks5NoAuth       = 0x00
	socks5UserPassAuth = 0x02
	socks5CmdNotSup    = 0x07
	socks5GenFailure   = 0x01
	socks5TTLExpired   = 0x06 // RFC 1928: TTL expired - used here for "we waited and nothing came"
	replyNotAllowed    = 0x02 // connection not allowed by ruleset
)

type clientParams struct {
	ListenAddr string `env:"CLIENT_LISTEN_ADDR" envDefault:"127.0.0.1:1080"`
	ServerAddr string `env:"SERVER_ADDR" envDefault:""`
	ProxyUser  string `env:"PROXY_USER" envDefault:""`
	ProxyPass  string `env:"PROXY_PASS" envDefault:""`
	PSK        string `env:"OBFS_PSK" envDefault:""`
	MaxPadding int    `env:"OBFS_MAX_PADDING" envDefault:"256"`
	MTU        int    `env:"OBFS_MTU" envDefault:"1400"`
	// NodeID must match the server's OBFS_NODE_ID. It is not sent anywhere;
	// it goes into the key derivation, so a wrong one fails like a wrong
	// PSK (plan task Ф5-4).
	NodeID string `env:"OBFS_NODE_ID" envDefault:""`
	// Cipher overrides the automatic choice. Empty is the normal setting:
	// the client then takes AES where the processor has AES instructions
	// and ChaCha20 where it has not (plan task Ф5-5). The server accepts
	// either, so this is a knob for measuring, not for matching.
	Cipher string `env:"OBFS_CIPHER" envDefault:""`
	// Prologue is how the prologue looks on the wire: "printable" encodes
	// it so the connection opens with printable characters, which is what
	// exempts the first packet from a fully-encrypted-traffic policy, and
	// "raw" is the pre-phase-5 wire. The server accepts both, so this only
	// has to be lowered when the server is older than the client
	// (docs/field/migration.md).
	Prologue string `env:"OBFS_PROLOGUE" envDefault:"printable"`
	// SplitOpening sends the opening in a packet of its own, ahead of the
	// first frames. It is the second exemption measured in the field: a
	// filter that skips first packets below a length of its own lets the
	// opening through, and the decision it makes there covers the rest of
	// the connection (docs/field/stealth.md). Off by default, because a
	// short packet in a fixed place is a shape of its own; turn it on for
	// a path where the encoded prologue alone is not enough. The server
	// needs no setting: both ends read the opening the same way.
	SplitOpening bool `env:"OBFS_SPLIT_OPENING" envDefault:"false"`
	// MemberID and MemberKey are this client's own account on the tunnel,
	// as opposed to the deployment-wide PSK everyone shares. With them set,
	// the server knows who is calling before the first frame is decrypted
	// and asks for no password at all (plan task Ф5-5). MemberID must be
	// the username in the server's user file; MemberKey is that account's
	// tunnel_key, base64.
	MemberID     string `env:"OBFS_MEMBER_ID" envDefault:""`
	MemberKey    string `env:"OBFS_MEMBER_KEY" envDefault:""`
	RouteDomains string `env:"ROUTE_DOMAINS" envDefault:""`

	// A tunnel that goes quiet is dropped by whatever sits on the path: a
	// reverse proxy after about a minute, Cloudflare after about 100 seconds,
	// a mobile CGNAT sooner than either - and s5core itself after READ_TIMEOUT,
	// which is 30 seconds by default and is the shortest of them all. The
	// interval has to clear the shortest, so it is drawn from a range whose
	// top is well under it; it is drawn anew each time so that holding the
	// connection open does not itself become the thing that identifies it.
	// Setting the minimum to zero turns it off.
	//
	// The measured matrix behind these numbers is in README, under Keepalive.
	// WireGuard's persistent keepalive is 25 seconds and OpenVPN pings every
	// 10, so this range is where the rest of the field sits too.
	KeepaliveMin time.Duration `env:"KEEPALIVE_MIN" envDefault:"10s"`
	KeepaliveMax time.Duration `env:"KEEPALIVE_MAX" envDefault:"20s"`

	// How long a shutdown waits for connections that are still carrying
	// traffic before it stops waiting.
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"10s"`

	// WebSocket stealth transport
	WSUrl          string `env:"WS_URL" envDefault:""`
	WSHost         string `env:"WS_HOST" envDefault:""`
	WSOrigin       string `env:"WS_ORIGIN" envDefault:""`
	WSUserAgent    string `env:"WS_USER_AGENT" envDefault:""`
	TLSFingerprint string `env:"TLS_FINGERPRINT" envDefault:""`
	// ServerName is the SNI presented to the server and the name its
	// certificate is verified against. It was read from the environment and
	// never used until plan task Ф6-4, so a deployment that set it believed
	// it had moved its SNI and had not.
	ServerName string `env:"SERVER_NAME" envDefault:""`
	// Until now the stealth transport accepted any certificate at all: the
	// uTLS dialer was built with InsecureSkipVerify and a comment saying the
	// caller should pin the certificate, and no caller did. These two settings
	// are how a private deployment is trusted without trusting everyone.
	WSCAFile string   `env:"WS_CA_FILE" envDefault:""`
	WSPins   []string `env:"WS_PIN_SHA256" envSeparator:"," envDefault:""`

	WSMinFrame    int `env:"WS_MIN_FRAME" envDefault:"256"`
	WSMaxFrame    int `env:"WS_MAX_FRAME" envDefault:"4096"`
	WSMaxJitterMs int `env:"WS_MAX_JITTER_MS" envDefault:"0"`

	// Without these two the client had no deadline anywhere: a server that
	// accepted the TCP connection and then said nothing left the application
	// waiting forever, with not one line in the log. That is the shape of the
	// field report behind plan task Ф3-1.
	DialTimeout      time.Duration `env:"DIAL_TIMEOUT" envDefault:"10s"`
	HandshakeTimeout time.Duration `env:"HANDSHAKE_TIMEOUT" envDefault:"15s"`

	// The timezone check asks a third party where the server is, which pairs
	// the client address with the proxy address in someone else's logs and
	// puts a recognisable request on the wire right before every connection to
	// the proxy. It is a convenience, so it is opt-in: either this variable or
	// the explicit "s5client timezone" command.
	TimezoneCheck bool `env:"TIMEZONE_CHECK" envDefault:"false"`

	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// Transport is which transport to use: obfs, ws, or auto (plan task
	// Ф5-7). Auto is the configured default - ws when WS_URL is set, obfs
	// otherwise - overridden by the server's advice when there is one,
	// with the other transport tried when the chosen one fails to set up.
	// A pinned transport is used regardless of both.
	Transport string `env:"TRANSPORT" envDefault:"auto"`
	// TransportCooldown is how long a transport that failed to set up is
	// rested while the other one is used. Zero disables the switch.
	TransportCooldown time.Duration `env:"TRANSPORT_COOLDOWN" envDefault:"5m"`
	// Format is the obfuscation format: v1 (docs/veil-spec.md), legacy
	// (the format before it, for a server that has not been updated), or
	// auto - v1 first, legacy for FormatReprobe after a server accepted
	// the connection and did not answer. The legacy format is scheduled
	// for removal; see docs/field/migration.md.
	Format        string        `env:"OBFS_FORMAT" envDefault:"auto"`
	FormatReprobe time.Duration `env:"OBFS_FORMAT_REPROBE" envDefault:"10m"`

	// rootCAs is WSCAFile after it has been read; unexported, so env.Parse
	// leaves it alone.
	rootCAs *x509.CertPool
	// policy is the shared decision state built from Transport and Format;
	// transport and format are what it chose for this attempt. All three
	// are unexported for the same reason as rootCAs.
	policy    *clientPolicy
	transport transportKind
	format    formatKind
}

// loadRootCAs reads a PEM file of trusted certificates. The pool replaces the
// system roots rather than extending them: a deployment that names its own CA
// has said which certificate it expects, and the public CA system is not part
// of that answer.
func loadRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read WS_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("WS_CA_FILE %s contains no certificate", path)
	}
	return pool, nil
}

func main() {
	if _, err := logging.Setup(os.Stdout); err != nil {
		slog.Warn("Invalid LOG_LEVEL, falling back to info", "error", err)
	}

	var cfg clientParams
	if err := env.Parse(&cfg); err != nil {
		slog.Error("Failed to parse env config", "error", err)
		os.Exit(1)
	}

	// "s5client timezone" runs the GeoIP lookup and nothing else: the check is
	// still available to anyone who wants it, it just no longer happens behind
	// the user's back on every start.
	if len(os.Args) > 1 && os.Args[1] == "timezone" {
		if cfg.ServerAddr == "" {
			slog.Error("SERVER_ADDR is required")
			os.Exit(1)
		}
		checkTimezone(cfg.ServerAddr)
		return
	}

	if cfg.ServerAddr == "" {
		slog.Error("SERVER_ADDR is required")
		os.Exit(1)
	}
	if cfg.PSK == "" || len(cfg.PSK) != 32 {
		slog.Error("OBFS_PSK must be exactly 32 bytes")
		os.Exit(1)
	}

	if _, err := memberKey(cfg); err != nil {
		slog.Error("OBFS_MEMBER_KEY is unusable", "error", err)
		os.Exit(1)
	}
	if cfg.MemberKey != "" && cfg.MemberID == "" {
		slog.Error("OBFS_MEMBER_KEY is set without OBFS_MEMBER_ID: the server needs the name the key belongs to")
		os.Exit(1)
	}

	if !obfs.PrologueEncoding(cfg.Prologue).Valid() {
		slog.Error("OBFS_PROLOGUE is not a prologue encoding this build knows",
			"value", cfg.Prologue, "known", []string{string(obfs.ProloguePrintable), string(obfs.PrologueRaw)})
		os.Exit(1)
	}

	if !veil.IsCipher(clientCipher(cfg.Cipher)) {
		// Caught here rather than at the first connection: an unknown name
		// would otherwise look like a server that refuses everything.
		slog.Error("OBFS_CIPHER is not a cipher this build knows",
			"value", cfg.Cipher, "known", veil.Ciphers())
		os.Exit(1)
	}

	if cfg.KeepaliveMin < 0 || cfg.KeepaliveMax < 0 {
		slog.Error("KEEPALIVE_MIN and KEEPALIVE_MAX must not be negative")
		os.Exit(1)
	}
	if cfg.KeepaliveMin > 0 && cfg.KeepaliveMax < cfg.KeepaliveMin {
		// A max below the min would silently collapse the draw to a constant,
		// which is the one shape the interval exists to avoid.
		slog.Error("KEEPALIVE_MAX must be at least KEEPALIVE_MIN",
			"min", cfg.KeepaliveMin, "max", cfg.KeepaliveMax)
		os.Exit(1)
	}

	pool, err := loadRootCAs(cfg.WSCAFile)
	if err != nil {
		slog.Error("Invalid TLS trust configuration", "error", err)
		os.Exit(1)
	}
	cfg.rootCAs = pool

	policy, err := newClientPolicy(cfg)
	if err != nil {
		slog.Error("Transport policy is not usable", "error", err)
		os.Exit(1)
	}
	cfg.policy = policy

	startupChecks(cfg)

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
		append([]any{
			"version", buildinfo.Version(),
			"log_level", logging.Level(),
			"listen", cfg.ListenAddr,
			"server", cfg.ServerAddr,
			"auth", cfg.ProxyUser != "",
			"mtu", cfg.MTU,
			"max_padding", cfg.MaxPadding,
			"route_domains", len(routePatterns),
		}, policy.describe()...)...,
	)

	if len(routePatterns) > 0 {
		slog.Info("Domain routing enabled", "patterns", routePatterns)
	} else {
		slog.Info("Domain routing disabled - all traffic will be tunneled")
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("Failed to listen", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	sigCh := make(chan os.Signal, 1)
	signals.Notify(sigCh, signals.Terminate...)

	hupCh := make(chan os.Signal, 1)
	hupWanted := signals.Notify(hupCh, signals.Reload...)

	usrCh := make(chan os.Signal, 1)
	usrWanted := signals.Notify(usrCh, signals.ToggleDebug...)

	var wg sync.WaitGroup

	go func() {
		<-sigCh
		slog.Info("Shutting down s5client...")
		listener.Close()
	}()

	// Waiting for live connections is right; waiting for them without end is
	// not. A tunnel carrying a long download, or one whose far end has
	// stopped answering, would otherwise keep a client that was asked to stop
	// running until it is killed.
	defer func() {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(cfg.ShutdownTimeout):
			slog.Warn("Connections still open at shutdown, exiting anyway",
				"waited", cfg.ShutdownTimeout)
		}
	}()

	// A platform without these signals never sends on the channel; the
	// goroutines are simply not started, because listening for no signal at
	// all means listening for every signal.
	if hupWanted {
		go func() {
			for range hupCh {
				if level, err := logging.SetLevelFromEnv(); err != nil {
					slog.Error("Failed to apply LOG_LEVEL on SIGHUP, keeping previous", "error", err, "log_level", level)
				} else {
					slog.Info("Log level applied", "log_level", level)
				}
			}
		}()
	}

	if usrWanted {
		go func() {
			for range usrCh {
				slog.Info("Log level toggled by SIGUSR1", "log_level", logging.ToggleDebug())
			}
		}()
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Error("Accept error", "error", err)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleClient(c, cfg, routePatterns)
		}(clientConn)
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

	// Step 4-5: Establish obfs tunnel and forward SOCKS5 request. The
	// policy decides the transport and format of this attempt (plan task
	// Ф5-7); from here on cfg is what was actually used.
	obfsConn, cfg, err := dialTunnel(cfg, wireReq)
	if err != nil {
		// A timeout here used to be invisible: no deadline, no error, no log
		// line, and an application waiting forever. The phase says which step
		// went silent, which is the difference between "the server is
		// unreachable" and "the server accepted us and never replied".
		logTunnelFailure(err, destFQDN, cfg)
		clientConn.Write([]byte{socks5Ver, replyForTunnelError(err), 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return
	}
	defer obfsConn.Close()

	// Handle based on command
	if cmd == socks5.AssociateCommand {
		handleUDPAssociate(clientConn, obfsConn, destFQDN, cfg)
		return
	}

	// Handle normal CONNECT
	// Read CONNECT response from server, still under the handshake deadline.
	connectResp := make([]byte, 512)
	rn, err := obfsConn.Read(connectResp)
	if err != nil {
		wrapped := &tunnelError{phase: phaseConnectReply, err: err}
		logTunnelFailure(wrapped, destFQDN, cfg)
		clientConn.Write([]byte{socks5Ver, replyForTunnelError(wrapped), 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return
	}
	// The tunnel is up: relayed traffic must not inherit the setup deadline.
	clearDeadline(obfsConn)

	// Forward CONNECT response to client
	if _, err := clientConn.Write(connectResp[:rn]); err != nil {
		return
	}

	if rn >= 2 && connectResp[1] != 0x00 {
		return
	}

	// Step 6: Bidirectional relay
	slog.Info("TCP Tunnel established", "domain", destFQDN, "server", cfg.ServerAddr,
		"transport", cfg.effectiveTransport(), "format", cfg.effectiveFormat())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(obfsConn, clientConn) //nolint:errcheck
		endWrite(obfsConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, obfsConn) //nolint:errcheck
		endWrite(clientConn)
	}()

	wg.Wait()
}

// endWrite tells the other end that this side has nothing more to send.
//
// Without it the relay hung: the application closing its connection ended one
// copy, while the other sat reading the tunnel for a peer that had no reason
// to close it, so handleClient never returned, its deferred Close never ran,
// and a client asked to shut down waited for goroutines that would wait
// forever. It was visible as a client that ignored SIGTERM while any tunnel
// had ever been opened.
//
// A half-close is the right signal and the one the server sends. Both ends of
// a tunnel now carry it whatever the transport underneath: the obfuscation
// layer sends a FIN frame of its own (plan task Ф4-9), because a WebSocket has
// no half-close of its own and would otherwise have to close the whole
// connection, losing the traffic still in flight the other way. The fallback
// below is for a transport that has neither - none is in the tree today, and
// it is a closed connection rather than a hang.
func endWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	c.Close() //nolint:errcheck
}

// socks5Handshake reads the SOCKS5 greeting and request from the client.
// Returns the raw request bytes, the command type, parsed destination FQDN, and any error.
func socks5Handshake(clientConn net.Conn) (req []byte, cmd byte, destFQDN string, err error) {
	// Read SOCKS5 greeting exactly to avoid relying on packet boundaries.
	if err := readSocks5Greeting(clientConn); err != nil {
		return nil, 0, "", fmt.Errorf("invalid SOCKS5 greeting: %w", err)
	}

	// Respond: no auth required locally
	if _, err := clientConn.Write([]byte{socks5Ver, socks5Success}); err != nil {
		return nil, 0, "", fmt.Errorf("failed to send greeting response: %w", err)
	}

	// Read SOCKS5 request exactly to avoid partial-read stalls and truncation.
	req, cmd, destFQDN, err = readSocks5Request(clientConn)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid SOCKS5 request: %w", err)
	}

	if cmd != socks5.ConnectCommand && cmd != socks5.AssociateCommand {
		_, _ = clientConn.Write([]byte{socks5Ver, socks5CmdNotSup, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
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
	clientConn.Write([]byte{socks5Ver, replyNotAllowed, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	return false
}

// dialObfsTunnel establishes an obfuscated connection to the server and forwards
// the SOCKS5 handshake through the encrypted tunnel.
// tunnelPhase names the step of tunnel setup where something went wrong. It
// exists so a failure says "the server accepted the connection and never
// answered the greeting" instead of a bare i/o timeout.
type tunnelPhase string

const (
	phaseDial     tunnelPhase = "dial"
	phaseGreeting tunnelPhase = "greeting"
	phaseAuth     tunnelPhase = "auth"
	// phaseAuthRejected is the server answering "no" to the credentials,
	// as opposed to phaseAuth, which is the server going quiet where an
	// answer was due. The two look the same to the caller and mean
	// opposite things about the path: a rejection is proof that the
	// obfuscation worked, because the frames were decrypted and a SOCKS5
	// exchange took place. Only the silent case says anything about the
	// format or the PSK, so only the silent case may move the policy.
	phaseAuthRejected tunnelPhase = "auth_rejected"
	phaseConnect      tunnelPhase = "connect"
	phaseConnectReply tunnelPhase = "connect_reply"
)

// tunnelError carries the phase alongside the cause.
type tunnelError struct {
	phase tunnelPhase
	err   error
}

func (e *tunnelError) Error() string { return string(e.phase) + ": " + e.err.Error() }
func (e *tunnelError) Unwrap() error { return e.err }

func tunnelFail(phase tunnelPhase, format string, args ...any) error {
	return &tunnelError{phase: phase, err: fmt.Errorf(format, args...)}
}

// isTimeout reports whether an error is a deadline or network timeout.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tunnelPhaseOf returns the phase an error was raised in, or an empty phase.
func tunnelPhaseOf(err error) tunnelPhase {
	var te *tunnelError
	if errors.As(err, &te) {
		return te.phase
	}
	return ""
}

// replyForTunnelError maps a tunnel failure to the SOCKS5 reply the local
// application gets. A timeout is reported as TTL expired, everything else as a
// general failure - both of which applications handle, unlike the command-not-
// supported code this used to send for every kind of failure.
func replyForTunnelError(err error) byte {
	if isTimeout(err) {
		return socks5TTLExpired
	}
	return socks5GenFailure
}

// logTunnelFailure records a failed tunnel setup at the level that matches
// what happened: a timeout is a warning about a specific phase, anything else
// is an error. The destination is included because this log lives on the
// user's own machine, where it is the only way to tell which site stalled;
// docs/design/observability-policy.md governs the server, not the client.
func logTunnelFailure(err error, dest string, cfg clientParams) {
	attrs := []any{
		"phase", string(tunnelPhaseOf(err)),
		"dest", dest,
		"server", cfg.ServerAddr,
		"transport", cfg.effectiveTransport(),
		"format", cfg.effectiveFormat(),
		"error", err,
	}
	if hint := setupHint(err, cfg); hint != "" {
		attrs = append(attrs, "hint", hint)
	}
	if isTimeout(err) {
		attrs = append(attrs, "dial_timeout", cfg.DialTimeout, "handshake_timeout", cfg.HandshakeTimeout)
		slog.Warn("Tunnel setup timed out", attrs...)
		return
	}
	slog.Error("Tunnel setup failed", attrs...)
}

// setupHint names the two causes a client cannot be told about over the wire.
//
// A server that does not recognise a connection says nothing and closes: it
// must not answer a wrong key faster than a wrong payload, or an active probe
// learns there is a server here at all. The cost of that silence lands on the
// operator, who sees a connection that dials fine and then stalls, with no
// reason given anywhere.
//
// Two things produce exactly that picture: a PSK that does not match, and a
// clock too far out for the epoch window (plan task Ф5-3). Neither is
// detectable from this side, so the hint names both rather than guessing.
// It is printed only past the dial phase, where the server has already
// accepted the connection - before that, the network is the likelier story.
func setupHint(err error, cfg clientParams) string {
	if cfg.PSK == "" {
		return ""
	}
	switch tunnelPhaseOf(err) {
	case phaseAuthRejected:
		// The server answered. Naming the PSK and the clock here would
		// send the operator after the two things this failure rules out.
		return ""
	case phaseGreeting, phaseAuth, phaseConnect, phaseConnectReply:
		if cfg.effectiveFormat() == formatLegacy {
			return "the server accepted the connection and then went quiet while the client spoke the previous " +
				"obfuscation format: check OBFS_PSK, and if the server is a current build, set OBFS_FORMAT=v1 or leave it on auto"
		}
		return fmt.Sprintf("the server accepted the connection and then went quiet: check OBFS_PSK and OBFS_NODE_ID, "+
			"and check this machine's clock - the tunnel binds its keys to the hour and tolerates about %d "+
			"hours of skew (local time is now %s); a server that has not been updated is also silent, "+
			"and OBFS_FORMAT=auto tries the previous format next",
			veil.DefaultEpochWindow, time.Now().Format(time.RFC3339))
	default:
		return ""
	}
}

// clearDeadline removes the handshake deadline once the tunnel is up. Relayed
// traffic must not inherit it: a long-lived connection is not a stalled one.
func clearDeadline(conn net.Conn) {
	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("Could not clear the handshake deadline", "error", err)
	}
}

// startupChecks holds everything the client does before it starts listening.
// It exists as a function so that a test can assert the one property that
// matters here: starting the client opens no connection to anyone but the
// server.
func startupChecks(cfg clientParams) {
	if cfg.TimezoneCheck {
		checkTimezone(cfg.ServerAddr)
	}
}

// dialServer opens the raw transport to the server: a WebSocket when WS_URL is
// set, a plain TCP connection otherwise. It is a variable so that timing tests
// can hand back an in-memory pipe - a real socket cannot run inside a
// synctest bubble, because its deadlines belong to the kernel clock.
var dialServer = func(cfg clientParams) (net.Conn, error) {
	if cfg.usesWS() {
		wsOpts := ws.DialOpts{
			URL:            cfg.WSUrl,
			Host:           cfg.WSHost,
			ServerName:     cfg.ServerName,
			Origin:         cfg.WSOrigin,
			UserAgent:      cfg.WSUserAgent,
			TLSFingerprint: cfg.TLSFingerprint,
			RootCAs:        cfg.rootCAs,
			PinSHA256:      cfg.WSPins,
		}
		wsConn, err := ws.Dial(wsOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to dial WS: %w", err)
		}
		if cfg.WSMaxFrame > 0 {
			return ws.NewShapedConn(wsConn, cfg.WSMinFrame, cfg.WSMaxFrame, time.Duration(cfg.WSMaxJitterMs)*time.Millisecond), nil
		}
		return wsConn, nil
	}

	ctx := context.Background()
	if cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.DialTimeout)
		defer cancel()
	}
	conn, err := dialOutbound(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	return conn, nil
}

func dialObfsTunnel(cfg clientParams, connectReq []byte) (net.Conn, error) {
	serverConn, err := dialServer(cfg)
	if err != nil {
		return nil, &tunnelError{phase: phaseDial, err: err}
	}

	// Every read below is covered by one deadline. It is cleared by the caller
	// once the CONNECT reply has arrived, so it bounds setup and nothing else.
	if cfg.HandshakeTimeout > 0 {
		if err := serverConn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout)); err != nil {
			serverConn.Close()
			return nil, &tunnelError{phase: phaseDial, err: fmt.Errorf("failed to set handshake deadline: %w", err)}
		}
	}

	obfsConn, err := wrapTunnel(serverConn, cfg)
	if err != nil {
		serverConn.Close()
		return nil, &tunnelError{phase: phaseDial, err: fmt.Errorf("failed to create obfs conn: %w", err)}
	}

	// Send SOCKS5 greeting with supported auth methods.
	// In no-auth mode we can safely pipeline CONNECT behind the greeting
	// and save one WAN RTT.
	if cfg.ProxyUser != "" {
		// Offer both no-auth and user/pass to preserve compatibility with
		// existing server configs.
		if _, err := obfsConn.Write([]byte{socks5Ver, socks5UserPassAuth, 0x00, 0x02}); err != nil {
			obfsConn.Close()
			return nil, tunnelFail(phaseGreeting, "failed to send greeting: %w", err)
		}
	} else {
		pipelined := make([]byte, 0, 3+len(connectReq))
		pipelined = append(pipelined, socks5Ver, 0x01, socks5NoAuth)
		pipelined = append(pipelined, connectReq...)
		if _, err := obfsConn.Write(pipelined); err != nil {
			obfsConn.Close()
			return nil, tunnelFail(phaseGreeting, "failed to send greeting: %w", err)
		}
	}

	// Read server greeting response
	var resp [2]byte
	if _, err := io.ReadFull(obfsConn, resp[:]); err != nil {
		obfsConn.Close()
		return nil, tunnelFail(phaseGreeting, "failed to read server greeting: %w", err)
	}

	// Handle auth method selected by server
	switch resp[1] {
	case 0x00:
		if cfg.ProxyUser == "" {
			return obfsConn, nil
		}
		// No auth required - proceed
	case 0x02:
		// User/pass auth (RFC 1929)
		if cfg.ProxyUser == "" {
			obfsConn.Close()
			return nil, tunnelFail(phaseAuthRejected, "server requires auth but PROXY_USER not set")
		}
		authReq := buildUserPassAuthPacket(cfg.ProxyUser, cfg.ProxyPass)
		pipelined := make([]byte, 0, len(authReq)+len(connectReq))
		pipelined = append(pipelined, authReq...)
		pipelined = append(pipelined, connectReq...)
		if _, err := obfsConn.Write(pipelined); err != nil {
			obfsConn.Close()
			return nil, tunnelFail(phaseAuth, "failed to send auth: %w", err)
		}
		if err := readUserPassAuthResponse(obfsConn); err != nil {
			obfsConn.Close()
			phase := phaseAuth
			if errors.Is(err, errAuthRejected) {
				phase = phaseAuthRejected
			}
			return nil, &tunnelError{phase: phase, err: err}
		}
		return obfsConn, nil
	case 0xFF:
		obfsConn.Close()
		return nil, tunnelFail(phaseAuthRejected, "server rejected all auth methods")
	default:
		obfsConn.Close()
		return nil, tunnelFail(phaseAuthRejected, "unsupported auth method: 0x%02x", resp[1])
	}

	// Forward CONNECT request
	if _, err := obfsConn.Write(connectReq); err != nil {
		obfsConn.Close()
		return nil, tunnelFail(phaseConnect, "failed to send CONNECT: %w", err)
	}

	return obfsConn, nil
}

// wrapTunnel puts the obfuscation format of this attempt over the raw
// transport. The current format carries the client's hello - its build and
// the transport it arrived on, for the server's telemetry - and takes the
// server's advice back for the policy (plan task Ф5-7). The previous format
// has neither; it is here for a server that has not been updated yet.
func wrapTunnel(serverConn net.Conn, cfg clientParams) (net.Conn, error) {
	if cfg.effectiveFormat() == formatLegacy {
		return legacy.NewConn(serverConn, legacy.Config{
			PSK:        []byte(cfg.PSK),
			MaxPadding: cfg.MaxPadding,
			MTU:        cfg.MTU,
		})
	}
	obfsCfg := obfs.Config{
		PSK:              []byte(cfg.PSK),
		MaxPadding:       cfg.MaxPadding,
		MTU:              cfg.MTU,
		KeepaliveMin:     cfg.KeepaliveMin,
		KeepaliveMax:     cfg.KeepaliveMax,
		Scheme:           obfsScheme(cfg),
		PrologueEncoding: obfs.PrologueEncoding(cfg.Prologue),
		SplitOpening:     cfg.SplitOpening,
		Hello: &obfs.Hello{
			Version:   buildinfo.Version(),
			Transport: string(cfg.effectiveTransport()),
		},
	}
	if cfg.policy != nil {
		obfsCfg.OnAdvice = cfg.policy.onAdvice
	}
	return obfs.NewClientConn(serverConn, obfsCfg)
}

// effectiveFormat is the format of this attempt; unset means the current
// one, which is what a configuration built by hand gets.
func (cfg clientParams) effectiveFormat() formatKind {
	if cfg.format == "" {
		return formatV1
	}
	return cfg.format
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

// errAuthRejected marks the one auth failure that came back as an answer
// rather than as silence: the server read the credentials and said no.
var errAuthRejected = errors.New("the server rejected these credentials")

func readUserPassAuthResponse(conn io.Reader) error {
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("%w (status: 0x%02x)", errAuthRejected, resp[1])
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
		addrPart = make([]byte, 1+int(domainLen[0]))
		addrPart[0] = domainLen[0]
		if _, err := io.ReadFull(r, addrPart[1:]); err != nil {
			return nil, 0, "", err
		}
		destFQDN = string(addrPart[1:])
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
// IDN domains are normalized to ASCII (punycode) before comparison.
func matchDomain(fqdn string, patterns []string) bool {
	fqdn = strings.ToLower(fqdn)
	if ascii, err := idna.ToASCII(fqdn); err == nil {
		fqdn = ascii
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if ascii, err := idna.ToASCII(p); err == nil {
			p = ascii
		}

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

// clientCipher is which AEAD this client asks for. Unset means the one this
// machine's processor is good at: AES where AES instructions exist, ChaCha20
// where they do not. Measured on an aarch64 router: with the instructions AES
// is 3.4 times faster than ChaCha20, without them ChaCha20 is 5.9 times faster
// than AES (plan task Ф5-5, docs/benchmarks/arm-router.md).
//
// The choice is not negotiated: it goes into the prologue MAC, the server
// accepts either and reads which one was taken. So an explicit setting only
// has to be valid, not to match anything on the far end.
func clientCipher(name string) veil.Cipher {
	if name == "" {
		return veil.PreferredCipher()
	}
	return veil.Cipher(name)
}

// memberKey decodes this client's own tunnel key, if it has one. An empty
// setting is not an error: the client then connects over the deployment's
// shared account, the way every client did before plan task Ф5-5.
func memberKey(cfg clientParams) ([]byte, error) {
	if cfg.MemberKey == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(cfg.MemberKey)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(key) != veil.MemberKeySize {
		return nil, fmt.Errorf("decodes to %d bytes, need %d", len(key), veil.MemberKeySize)
	}
	return key, nil
}

// obfsScheme is how this client authenticates its first frame: the hour and
// the context always, plus its own identity when it has a key of its own.
//
// With a key, the server resolves the account from the prologue and asks for
// no password - which is both cheaper and stronger than one. Without it,
// nothing changes.
func obfsScheme(cfg clientParams) veil.Scheme {
	ctx := veil.Context{Cipher: clientCipher(cfg.Cipher), NodeID: cfg.NodeID}
	key, err := memberKey(cfg)
	if err != nil || key == nil {
		// A malformed key was already refused at startup; a client that
		// reaches here without one is a client of the shared account.
		return &veil.Clocked{Context: ctx}
	}
	return &veil.Roster{
		Clocked: veil.Clocked{Context: ctx},
		Member:  veil.Member{ID: cfg.MemberID, Key: key},
	}
}
