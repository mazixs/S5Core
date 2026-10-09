package s5server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/buildinfo"
	"github.com/mazixs/S5Core/internal/identity"
	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/s5core"
	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/internal/udpbuf"
	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/tlsdecoy"
	"github.com/mazixs/S5Core/pkg/veil"
	"go.opentelemetry.io/otel/metric"
)

// Server represents a controllable SOCKS5 server instance.
type Server struct {
	cfg           Config
	socks5        *socks5.Server
	nativeHub     atomic.Pointer[nativeudp.Hub]
	nativeMetrics metric.Registration
	udpMetrics    metric.Registration
	// nativeCounters is shared by every 0x84 association of the server.
	nativeCounters *socks5.NativeCounters
	udpCounters    *socks5.UDPRelayCounters
	lifeMu         sync.Mutex
	run            *serverRun
	running        bool

	// mu защищает поля слушателей: они заполняются в Start, а читаются
	// из Stop, WSAddr, Addr, UpdateWhitelist и UpdateTimeouts - как правило
	// из другой горутины (Start блокируется до остановки сервера).
	mu sync.Mutex
	// controls survives Stop/Start and is applied before publishing any new
	// pipeline. cfg is immutable; runtime updates never race its readers.
	controls listenerControls
	// pipelines holds every listener the server runs, so that the controls
	// that are documented as affecting "the server" - the whitelist, the
	// timeouts - reach all of them. UpdateWhitelist used to touch only the
	// plain listener, which meant it worked on a third of the surface and
	// said nothing about the rest.
	pipelines  []*listenerPipeline
	obfsListen net.Listener
	wsListen   net.Listener
	userStore  *userstore.Store
	// members is the table the obfuscation layer resolves a client's
	// identity against, nil when no user file is configured. It is rebuilt
	// on reload and kept warm by a goroutine started in Start.
	members        *veil.Directory
	memberMu       sync.Mutex
	membersChanged chan struct{}
	// saltHistory is shared by every obfuscated listener: a replay recorded
	// on the obfs port and sent again over WebSocket is the same replay.
	saltHistory *obfs.SaltHistory
	// advice is what every new tunnel is told about the transport it should
	// use next (plan task Ф5-7). Atomic because SIGHUP replaces it while
	// listeners are accepting; nil sends nothing.
	advice atomic.Pointer[obfs.Advice]
	// versions fences the client_version label to a fixed number of
	// distinct builds, per server (docs/design/observability-policy.md).
	versions versionLabels
	// sessions holds the state machine of every live connection (plan task
	// Ф6-1). Every listener opens into it, and it is what the s5core_sessions
	// gauge counts at scrape time.
	sessions *session.Registry
	// sessionGauge is the registration of that gauge's callback, released on
	// Stop so a restarted server does not leave it pointing at a dead
	// registry.
	sessionGauge metric.Registration

	// boot names this server's process in its markers; journal is the
	// session journal while Start runs, nil when SessionLog is off.
	boot       atomic.Value // string, replaced at the beginning of each Start
	started    time.Time
	journal    atomic.Pointer[sessionJournal]
	endMetrics *connEndMetrics
	minutes    *minuteSummary
	connsEnded atomic.Int64
	reloads    atomic.Int64
	stopped    atomic.Bool

	logger *slog.Logger
	wg     sync.WaitGroup
}

// Each Start owns one cleanup and its completion. Stop cancels that run and
// waits for its owner; it never races WaitGroup.Wait against startup's Add.
type serverRun struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	stopErr error // published by closing done
}

// udpTunnelTuner builds the hook that tunes the socket of a 0x83 or 0x84 tunnel. A
// test replaces it to see the connection the hook is given.
var udpTunnelTuner = tcptune.Tuner

// NewServer initializes a new SOCKS5 server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	whitelist, err := parseWhitelist(cfg.AllowedIPs)
	if err != nil {
		return nil, err
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Собственные сообщения сервера идут в тот же логгер, что и сообщения
	// SOCKS5-ядра. Прежде здесь создавался отдельный обработчик с жестко
	// зашитым уровнем Info: переданный через Config логгер игнорировался,
	// а Debug-диагностика протокола была недостижима в принципе.
	logger := cfg.Logger

	applyWSDefaults(&cfg)
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.ObfsEnabled || cfg.WSEnabled {
		warnShortHandshake(logger, cfg.HandshakeTimeout)
	}
	// A zero dial budget is not "no limit", it is the operating system's own
	// two minutes, and a client waits out every one of them in the Dialing
	// state. Same for a frame that never completes.
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.FrameTimeout == 0 {
		cfg.FrameTimeout = DefaultFrameTimeout
	}
	// QuotaGrace is deliberately not defaulted: zero means "end the session
	// where the quota is noticed", which is a choice, not an omission.

	var server *Server
	nativeCounters := new(socks5.NativeCounters)
	udpCounters := new(socks5.UDPRelayCounters)
	socks5conf := &socks5.Config{
		Logger:                 cfg.Logger,
		Dial:                   cfg.Dial,
		DenyPrivateDest:        cfg.DenyPrivateDest,
		NativeCounters:         nativeCounters,
		UDPRelayCounters:       udpCounters,
		UDPDiagnosticsInterval: cfg.UDPDiagnosticsInterval,
		OnUDPReport:            udpReportHook(logger, cfg.UDPDiagnosticsInterval),
		// A node without UDP_PORT, or a listener without obfs keys, answers
		// 0x84 with port 0: the client then stays on 0x83 without another
		// connection.
		NativeUDP: func(conn net.Conn) (socks5.NativeAssociation, error) {
			hub := server.nativeHub.Load()
			if hub == nil {
				return nil, nil
			}
			keys, err := obfs.DatagramKeysOf(conn)
			if errors.Is(err, obfs.ErrNoDatagramKeys) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			peer, _ := netip.ParseAddr(host)
			return &nativeAssociation{hub: hub, session: hub.RegisterPeer(keys, peer)}, nil
		},
	}
	socks5conf.ObservePhase, socks5conf.CountPhase = phaseHooks(cfg.Telemetry)
	socks5conf.ObserveHalfClose = halfCloseHook(cfg.Telemetry)
	socks5conf.OnAssociationEnd = associationEndHook(cfg.Telemetry)
	socks5conf.OnUDPDrop = udpDropHook(cfg.Telemetry)
	socks5conf.OnConnEnd = func(conn net.Conn, end *socks5.ConnEnd) { server.connEnded(conn, end) }
	if !cfg.UDPTunnelTCPTuningOff {
		socks5conf.OnUDPTunnel = udpTunnelTuner(logger)
	}

	var uStore *userstore.Store
	var members *veil.Directory
	if cfg.RequireAuth {
		var err error
		if uStore, members, err = setupAccounts(cfg, logger, socks5conf); err != nil {
			return nil, err
		}
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

	s := &Server{
		cfg:            cfg,
		controls:       controlsFrom(cfg, whitelist),
		socks5:         srv,
		logger:         logger,
		userStore:      uStore,
		members:        members,
		membersChanged: make(chan struct{}, 1),
		saltHistory:    obfs.NewSaltHistory(cfg.ObfsReplayWindow),
		sessions:       session.NewRegistry(sessionTransitionObserver(cfg.Telemetry)),

		nativeCounters: nativeCounters,
		udpCounters:    udpCounters,

		endMetrics: newConnEndMetrics(cfg.Telemetry),
		minutes:    newMinuteSummary(),
	}
	s.boot.Store(logging.NewBoot())
	server = s
	gauge, err := registerSessionGauge(cfg.Telemetry, s.sessions)
	if err != nil {
		return nil, fmt.Errorf("failed to register the session gauge: %w", err)
	}
	s.sessionGauge = gauge
	udpMetrics, err := registerUDPRelayMetrics(cfg.Telemetry, udpCounters)
	if err != nil {
		if gauge != nil {
			_ = gauge.Unregister()
		}
		return nil, fmt.Errorf("failed to register UDP relay metrics: %w", err)
	}
	s.udpMetrics = udpMetrics
	// ValidateConfig has already refused an advice that does not parse or
	// names a transport this server does not run.
	if advice, _ := ParseTransportAdvice(cfg.TransportAdvice); advice != nil {
		s.advice.Store(advice)
	}
	return s, nil
}

// setupAccounts builds the account store for a server that requires
// authentication and wires it into the SOCKS5 configuration: credentials,
// traffic counters, quota checks and, with USERS_FILE, the member directory.
func setupAccounts(cfg Config, logger *slog.Logger, conf *socks5.Config) (*userstore.Store, *veil.Directory, error) {
	// One account mechanism, not two (plan task Ф6-3). The user store
	// used to be the path for USERS_FILE while PROXY_USER went into a
	// plain map, which meant quotas, expiry dates, roles and Argon2id
	// existed for one kind of deployment and not the other, and AddUser
	// did something different depending on which one it was. Without a
	// file the store simply has no file: it starts empty, AddUser fills
	// it, and everything downstream is the same code.
	uStore := userstore.NewStore(logger)
	uStore.SetKDFBudget(cfg.KDFMemoryBudget)
	if cfg.UsersFile != "" {
		if err := uStore.LoadFromFile(cfg.UsersFile); err != nil {
			return nil, nil, fmt.Errorf("failed to load users file: %w", err)
		}
	}
	uStore.SetVerifyObserver(authVerifyObserver(cfg.Telemetry))
	var store socks5.CredentialStore = userstore.NewCredentialAdapter(uStore)
	var members *veil.Directory

	// The lock-free per-user traffic counter, resolved once per
	// connection and shared by the TCP relay and both UDP modes. One
	// path, so a quota means the same thing whichever command the
	// client sent.
	conf.TrafficCounter = uStore.TrafficCounterFor
	// A quota is only a limit if it is checked while the session runs.
	// The relay asks this on the 64 KiB flush boundary it already has,
	// and the answer says why - a spent quota and an account that is
	// gone resolve to different terminal states (plan task Ф6-1).
	conf.SessionStatus = func(username string) socks5.SessionStatus {
		switch uStore.SessionStatus(username) {
		case userstore.SessionQuotaExceeded:
			return socks5.SessionQuotaExceeded
		case userstore.SessionExpired:
			return socks5.SessionExpired
		default:
			return socks5.SessionAllowed
		}
	}

	// Accounts that carry a tunnel key are recognised by the obfuscation
	// layer before the SOCKS5 handshake starts, and what it says outranks
	// a password (plan task Ф5-5).
	//
	// Only a file gets a member directory. A store with no file has no
	// keys to resolve yet, and building a directory anyway would put a
	// Roster prologue on the wire for deployments that never asked for
	// one - a change of wire format as a side effect of a refactor.
	if cfg.UsersFile != "" {
		directory, err := veil.NewDirectory(tunnelMembers(uStore))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build the tunnel member directory: %w", err)
		}
		members = directory
		conf.TunnelIdentity = obfs.IdentityOf
		conf.TunnelAccount = func(reference string) *socks5.SessionAccount {
			return boundSession(uStore.BindMember(reference))
		}
	}

	if cfg.Fail2BanRetries > 0 {
		authFailure, accountAlert := authHooks(cfg.Telemetry)
		store = identity.NewGuard(store, identity.Options{
			MaxRetries:     cfg.Fail2BanRetries,
			BanTime:        cfg.Fail2BanTime,
			Logger:         logger,
			OnAuthFailure:  authFailure,
			OnAccountAlert: accountAlert,
		})
	}

	cator := socks5.UserPassAuthenticator{Credentials: store, BindAccount: func(username string) *socks5.SessionAccount {
		return boundSession(uStore.Bind(username))
	}}
	conf.AuthMethods = []socks5.Authenticator{cator}
	return uStore, members, nil
}

func boundSession(binding *userstore.Binding) *socks5.SessionAccount {
	if binding == nil {
		return nil
	}
	return &socks5.SessionAccount{Name: binding.Name(), Counter: binding.Counter(), Status: func() socks5.SessionStatus {
		switch binding.Status() {
		case userstore.SessionQuotaExceeded:
			return socks5.SessionQuotaExceeded
		case userstore.SessionExpired:
			return socks5.SessionExpired
		default:
			return socks5.SessionAllowed
		}
	}}
}

// ReloadUsers reloads the user store from the configured file.
// Traffic counters are preserved across reloads.
func (s *Server) ReloadUsers() error {
	if s.userStore == nil || s.cfg.UsersFile == "" {
		// Since plan task Ф6-3 there is always a store; what a reload needs
		// is a file to reload from.
		return fmt.Errorf("the user store is not backed by a file (USERS_FILE is not set)")
	}
	if err := s.userStore.Reload(s.cfg.UsersFile); err != nil {
		return err
	}
	return s.refreshMembers()
}

// refreshMembers rebuilds the tunnel member directory from the store. Every
// change to the accounts goes through it, because the directory - not the
// store - is what the wire consults: a key that is still in it resolves a
// prologue, and a prologue that resolves is a session. A revoked account has
// to stop being resolvable now rather than at the next epoch or the next
// reload, and an account that has just been created has to start.
//
// This used to live inside ReloadUsers alone, so the file path revoked keys
// and the API path did not: RemoveUser deleted the account and left its key
// working, and AddUser created an account the tunnel could not name.
func (s *Server) refreshMembers() error {
	if err := s.rebuildMembers(); err != nil {
		return err
	}
	select {
	case s.membersChanged <- struct{}{}:
	default:
	}
	return nil
}

func (s *Server) rebuildMembers() error {
	if s.members == nil {
		return nil
	}
	s.memberMu.Lock()
	defer s.memberMu.Unlock()
	if err := s.members.SetMembers(tunnelMembers(s.userStore)); err != nil {
		return fmt.Errorf("failed to rebuild the tunnel member directory: %w", err)
	}
	if clashes := s.members.Collisions(); len(clashes) > 0 {
		s.logger.Error("Tunnel keys collide", "detail", clashes)
	}
	return nil
}

// tunnelMembers is the user store's view of who has a tunnel key, in the
// form pkg/veil resolves identities against.
func tunnelMembers(store *userstore.Store) []veil.Member {
	accounts := store.TunnelMembers()
	members := make([]veil.Member, 0, len(accounts))
	for _, a := range accounts {
		members = append(members, veil.Member{ID: a.Reference, Key: a.Key})
	}
	return members
}

// AddUser adds a new user for authentication. The password is hashed with
// Argon2id and the account is held in memory; with USERS_FILE set it reaches
// the file on the next flush.
//
// This is the process owner's API: it performs no role check, because a
// caller holding a *Server can also call Stop. A panel or an HTTP API acts on
// behalf of an account and must go through Server.As instead, which checks
// the account's role (plan task Ф6-3).
func (s *Server) AddUser(username, password string) error {
	if s.userStore == nil {
		return fmt.Errorf("authentication is not enabled")
	}

	if err := s.userStore.AddUser(username, password); err != nil {
		return err
	}
	return s.refreshMembers()
}

// RemoveUser removes a user from authentication. Like AddUser it is the
// process owner's API and performs no role check; see Server.As.
func (s *Server) RemoveUser(username string) error {
	if s.userStore == nil {
		return fmt.Errorf("authentication is not enabled")
	}

	if err := s.userStore.RemoveUser(username); err != nil {
		return err
	}
	// The key goes out of the directory with the account. Without this the
	// holder of a revoked key kept raising tunnels: the prologue still
	// resolved to the old identity, the SOCKS5 layer answered NoAuth on the
	// strength of it, and the relay never asked the account anything because
	// a deleted account has no traffic counter to ask through.
	return s.refreshMembers()
}

// SetRole changes what an account may do. Like AddUser and RemoveUser it is
// the process owner's API and performs no role check; see Server.As.
func (s *Server) SetRole(username string, role Role) error {
	if s.userStore == nil {
		return fmt.Errorf("authentication is not enabled")
	}
	if err := s.userStore.SetRole(username, role); err != nil {
		return err
	}
	// A role does not change a key, but it changes what the account is, and
	// the directory is rebuilt from the store rather than patched - so the
	// cheap thing to do is the correct one.
	return s.refreshMembers()
}

// UpdateWhitelist updates allowed IPs on every listener and retains the
// validated list for subsequent Start calls, including updates while stopped.
// It is the process owner's API and performs no role check; see Server.As.
func (s *Server) UpdateWhitelist(ips []string) error {
	whitelist, err := parseWhitelist(ips)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.whitelist = whitelist
	for _, p := range s.pipelines {
		p.setWhitelist(whitelist)
	}
	return nil
}

// parseWhitelist turns the configured client addresses into the form the
// listeners match against. It is the only parser of ALLOWED_IPS, and it is
// strict: an entry that is not an address fails the whole list.
//
// Startup used to have a parser of its own that skipped what it could not
// read. A list that was entirely wrong - one typo in one address, or a
// network written in CIDR because it looked like it would work - left nothing
// behind, and an empty whitelist is "no restriction". The setting whose job
// is to keep everyone out let everyone in, silently, while UpdateWhitelist
// rejected the very same list on the next SIGHUP (F10 in
// docs/reports/code-quality-audit-2026-09-20.md).
//
// What the list takes is single addresses, v4 or v6. A network is refused by
// name rather than ignored, because an operator who wrote one had a rule in
// mind and is entitled to be told it is not the rule they got.
func parseWhitelist(ips []string) ([]net.IP, error) {
	whitelist := make([]net.IP, 0, len(ips))
	for _, raw := range ips {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			// A trailing or doubled comma is punctuation, not an address.
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			whitelist = append(whitelist, ip)
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err == nil {
			return nil, fmt.Errorf(
				"ALLOWED_IPS holds the network %q; the list takes single addresses, so name each one", entry)
		}
		return nil, fmt.Errorf("ALLOWED_IPS holds %q, which is not an IP address", entry)
	}
	if len(whitelist) == 0 {
		// No addresses is no restriction, which is what an unset ALLOWED_IPS
		// means. It is reached only when nothing was written, never when
		// something was written and could not be read.
		return nil, nil
	}
	return whitelist, nil
}

// allPipelines returns the listeners started so far.
func (s *Server) allPipelines() []*listenerPipeline {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*listenerPipeline(nil), s.pipelines...)
}

// UpdateTimeouts updates read/write timeouts on the fly. Both are idle
// timeouts for the relay phase; the handshake budget is separate and changed
// through UpdateHandshakeTimeout.
//
// "On the fly" means from the next accepted connection onward: the values are
// copied into the connection wrapper at Accept time. The latest values also
// survive Stop/Start on this Server, even when updated while stopped.
func (s *Server) UpdateTimeouts(read, write time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.read, s.controls.write = read, write
	for _, p := range s.pipelines {
		p.setTimeouts(read, write)
	}
}

// UpdateHandshakeTimeout changes the budget for the setup phase on the fly,
// with the same "from the next connection onward" semantics as
// UpdateTimeouts.
func (s *Server) UpdateHandshakeTimeout(d time.Duration) {
	if d == 0 {
		d = DefaultHandshakeTimeout
	}
	if s.cfg.ObfsEnabled || s.cfg.WSEnabled {
		warnShortHandshake(s.logger, d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.handshake = d
	for _, p := range s.pipelines {
		p.setHandshakeTimeout(d)
	}
}

// spareAgeMax is the oldest a client's spare transport gets before a tunnel
// takes it (cmd/s5client/prewarm.go). The server's handshake budget starts at
// its accept, so a budget not above it closes spares before they are used.
const spareAgeMax = 10 * time.Second

func warnShortHandshake(logger *slog.Logger, d time.Duration) {
	if d > spareAgeMax {
		return
	}
	logger.Warn("HANDSHAKE_TIMEOUT is not above 10s: clients with PREWARM on lose their spare connections and wait out the budget on them",
		"handshake_timeout", d)
}

// UpdateSessionTimeouts changes the three budgets that belong to the session
// state machine rather than to the socket: how long one dial to a destination
// may take, how long an obfuscation frame may stay incomplete once its header
// has arrived, and how long a session drains after its account runs out. A
// zero grace ends such a session at once.
//
// Same "from the next accepted connection onward" semantics as
// UpdateTimeouts: a session's SLA is fixed when it is opened.
func (s *Server) UpdateSessionTimeouts(dial, frame, grace time.Duration) {
	if dial == 0 {
		dial = DefaultDialTimeout
	}
	if frame == 0 {
		frame = DefaultFrameTimeout
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.dial, s.controls.frame, s.controls.grace = dial, frame, grace
	for _, p := range s.pipelines {
		p.setSessionTimeouts(dial, frame, grace)
	}
}

// Start begins listening and serving traffic. It blocks until stopped.
func (s *Server) Start(ctx context.Context) (err error) {
	s.lifeMu.Lock()
	if s.running {
		s.lifeMu.Unlock()
		return errors.New("server is already starting or running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	run := &serverRun{ctx: runCtx, cancel: cancel, done: make(chan struct{})}
	s.run, s.running = run, true
	s.started = time.Now()
	s.stopped.Store(false)
	s.boot.Store(logging.NewBoot())
	s.mu.Lock()
	s.pipelines, s.obfsListen, s.wsListen = nil, nil, nil
	s.mu.Unlock()
	s.lifeMu.Unlock()

	// However this function ends, it leaves nothing listening. A server that
	// failed to open its second or third listener used to keep the ones it
	// had already opened: Start returned "failed to listen obfs on :1443",
	// the caller logged the failure and moved on, and the plain SOCKS5 port
	// went on accepting traffic that nobody thought was being served - with
	// no obfuscation, and with an operator convinced the node was down.
	// The same applies when a serving goroutine reports a failure: one dead
	// listener is a reason to stop the server, not a reason to keep the
	// other two running unattended.
	defer func() {
		run.cancel()
		s.shutdownListeners()
		if s.userStore != nil {
			run.stopErr = s.userStore.StopPeriodicFlush()
		}
		if s.stopped.CompareAndSwap(false, true) {
			s.minutes.emit(s.logger, s.journal.Load(), s.Boot())
			s.closeJournal()
		}
		s.unregisterRunMetrics()
		err = errors.Join(err, run.stopErr)
		s.lifeMu.Lock()
		s.running = false
		close(run.done)
		s.lifeMu.Unlock()
	}()
	if s.sessionGauge == nil {
		s.sessionGauge, err = registerSessionGauge(s.cfg.Telemetry, s.sessions)
		if err != nil {
			return fmt.Errorf("failed to register the session gauge: %w", err)
		}
	}
	if s.udpMetrics == nil {
		s.udpMetrics, err = registerUDPRelayMetrics(s.cfg.Telemetry, s.udpCounters)
		if err != nil {
			return fmt.Errorf("failed to register UDP relay metrics: %w", err)
		}
	}
	if err := s.openJournal(); err != nil {
		return err
	}
	udpbuf.Report(s.logger)
	if s.cfg.UDPPort != "" {
		addr := s.listenAddr(s.cfg.UDPPort)
		hub, err := nativeudp.Listen(addr, s.logger)
		if err != nil {
			return fmt.Errorf("failed to listen native UDP on %s: %w", addr, err)
		}
		s.nativeHub.Store(hub)
		registration, err := registerNativeMetrics(s.cfg.Telemetry, hub, s.nativeCounters)
		if err != nil {
			_ = hub.Close()
			s.nativeHub.Store(nil)
			return fmt.Errorf("native UDP metrics: %w", err)
		}
		s.mu.Lock()
		s.nativeMetrics = registration
		s.mu.Unlock()
		defer func() { s.nativeHub.Store(nil); _ = hub.Close() }()
		s.logger.Info("Native UDP enabled", "port", hub.Port())
	}

	// One counter for the whole server: see connLimiter.
	limiter := newConnLimiter(s.cfg.MaxConnections)
	if s.cfg.MaxConnections > 0 {
		s.logger.Info("Connection limit set", "max_connections", s.cfg.MaxConnections)
	}

	errCh := make(chan error, 3)
	serve := func(p *listenerPipeline) {
		s.mu.Lock()
		p.applyControls(s.controls)
		s.pipelines = append(s.pipelines, p)
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.socks5.ServeContext(runCtx, p); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}

	listenAddr := s.listenAddr(s.cfg.Port)

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	plain := newListenerPipeline(l, TransportPlain, s.cfg, s.cfg.Telemetry, limiter, s.sessions)

	s.logger.Info("Start listening proxy service (plain SOCKS5)", "address", listenAddr)
	serve(plain)

	// Start obfuscated listener on a separate port if enabled
	if s.cfg.ObfsEnabled && s.cfg.ObfsPort != "" {
		obfsAddr := s.listenAddr(s.cfg.ObfsPort)

		obfsListen, err := s.listenObfs(obfsAddr)
		if err != nil {
			return fmt.Errorf("failed to listen obfs on %s: %w", obfsAddr, err)
		}
		s.mu.Lock()
		s.obfsListen = obfsListen
		s.mu.Unlock()

		ol := newListenerPipeline(obfsListen, TransportObfs, s.cfg, s.cfg.Telemetry, limiter, s.sessions).
			withAdvice(s.currentAdvice).
			withObfs(s.obfsConfig(TransportObfs))

		s.logger.Info("Obfuscation ENABLED on separate port",
			"obfs_port", s.cfg.ObfsPort,
			"max_padding", s.cfg.ObfsMaxPadding,
			"mtu", s.cfg.ObfsMTU,
			"psk_length", len(s.cfg.ObfsPSK),
			"tfo", s.cfg.ObfsTFO,
		)
		serve(ol)
	} else {
		s.logger.Warn("Obfuscation DISABLED - only plain SOCKS5 is available")
	}

	// Start WebSocket-over-TLS listener if enabled
	if s.cfg.WSEnabled {
		wsAddr := s.cfg.WSAddr
		if wsAddr == "" {
			wsAddr = s.listenAddr("443")
		}

		// Пустая строка в списке сабпротоколов - не "любой", а требование
		// предложить пустой Sec-WebSocket-Protocol, которое ни один клиент
		// не выполняет.
		var subprotocols []string
		if s.cfg.WSSubprotocol != "" {
			subprotocols = []string{s.cfg.WSSubprotocol}
		}

		tdl, err := tlsdecoy.NewListener(tlsdecoy.Config{
			Addr:          wsAddr,
			CertFile:      s.cfg.WSCertFile,
			KeyFile:       s.cfg.WSKeyFile,
			WSPath:        s.cfg.WSPath,
			DecoyUpstream: s.cfg.WSDecoyUpstream,
			Subprotocols:  subprotocols,
			MaxFrame:      s.cfg.WSMaxFrame,
			EarlyData:     s.cfg.wsEarlyData(),
			Logger:        s.logger,
		})
		if err != nil {
			return fmt.Errorf("failed to start WS listener on %s: %w", wsAddr, err)
		}

		wl := newListenerPipeline(tdl, TransportWS, s.cfg, s.cfg.Telemetry, limiter, s.sessions).
			withShaper(s.cfg.WSMinFrame, s.cfg.WSMaxFrame, s.cfg.WSMaxJitter).
			withAdvice(s.wsAdvice).
			withObfs(s.obfsConfig(TransportWS))

		s.mu.Lock()
		s.wsListen = tdl
		s.mu.Unlock()

		s.logger.Info("WebSocket stealth transport ENABLED",
			"ws_addr", wsAddr,
			"ws_path", s.cfg.WSPath,
		)
		serve(wl)
	}

	// Одна строка про фактически поднятые слушатели. Опаснее самого разрыва
	// между конфигурацией и поведением то, что его нельзя увидеть в рантайме:
	// пользователь считает, что работает скрытно, а сервер слушает только
	// открытый порт.
	transports := s.enabledTransports()
	s.logger.Info("Active transports",
		"event", "process_start",
		"boot", s.Boot(),
		"summary", transportSummary(s.cfg),
		"version", buildinfo.Version(),
		"go_version", buildinfo.GoVersion(),
		"session_log", sessionLogMode(s.cfg),
	)
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.minutes.run(runCtx, s.logger, s.journal.Load, s.Boot()) }()
	s.cfg.Telemetry.RecordBuildInfo(buildinfo.Version(), buildinfo.GoVersion(), transports)

	// Keep the member table ahead of the clock, so that crossing an hour
	// boundary is not something a connection pays for.
	if s.members != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.maintainMembers(runCtx) }()
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
	case <-runCtx.Done():
		s.logger.Info("Server context canceled, shutting down...")
		// Every listener, not just the plain one. Closing one of three left
		// the other two accepting traffic after the server was told to stop.
		var firstErr error
		for _, p := range s.allPipelines() {
			if err := p.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	case err := <-errCh:
		return err
	}
}

// obfsConfig is the obfuscation configuration shared by the transports that
// use it. Only the failure observer differs, by transport label.
func (s *Server) obfsConfig(transport string) obfs.Config {
	return obfs.Config{
		PSK:        []byte(s.cfg.ObfsPSK),
		MaxPadding: s.cfg.ObfsMaxPadding,
		MTU:        s.cfg.ObfsMTU,
		History:    s.saltHistory,
		OnFailure:  obfsFailureObserver(s.cfg.Telemetry, s.logger, transport),
		Scheme:     s.obfsScheme(transport),
		// Who is out there, by build and transport (plan task Ф5-7). The
		// advice going the other way is attached per connection by the
		// pipeline, because it can change while the server runs.
		OnHello: clientHelloObserver(s.cfg.Telemetry, s.logger, transport, &s.versions),

		KeepaliveMin: s.cfg.ObfsKeepaliveMin,
		KeepaliveMax: s.cfg.ObfsKeepaliveMax,

		// A connection that never authenticated is held, not cut (plan
		// task Ф5-6): the handshake budget is what closes it, and it is
		// the same budget that closes a client which connected and then
		// said nothing. Without this the two are told apart by a clock.
		RefuseLinger: s.cfg.HandshakeTimeout,
	}
}

// obfsScheme builds the authentication scheme this server offers: the hour
// binding of task Ф5-3, plus whichever node identities of task Ф5-4 it
// answers to. Its own comes first, so the ordinary connection costs one MAC
// and a migration costs one more per extra identity.
func (s *Server) obfsScheme(transport string) veil.Scheme {
	// Every node identity this server answers to, its own first.
	nodes := []string{s.cfg.ObfsNodeID}
	for _, id := range s.cfg.ObfsAcceptNodeIDs {
		if id != s.cfg.ObfsNodeID {
			nodes = append(nodes, id)
		}
	}

	// Times every cipher, because a client picks the one its processor is
	// good at and the server has no say in it (plan task Ф5-5). The
	// preferred cipher comes first so that the common case is one HMAC.
	ciphers := veil.Ciphers()
	accepts := make([]veil.Context, 0, len(nodes)*len(ciphers))
	for _, c := range ciphers {
		for _, id := range nodes {
			accepts = append(accepts, veil.Context{Cipher: c, NodeID: id})
		}
	}

	// A Clocked holds the rate-limit state of its own diagnostic search, so
	// each one is built where it is used rather than copied.
	onSkew := obfsClockSkewObserver(s.cfg.Telemetry, s.logger, transport)
	if s.members == nil {
		return &veil.Clocked{Context: accepts[0], Accepts: accepts, OnClockSkew: onSkew}
	}

	// With a user file, the same prologue also carries who is calling
	// (plan task Ф5-5). Clients that have no key of their own keep
	// connecting as the shared account unless the operator says otherwise;
	// that fallback is one HMAC, and only for connections that are not
	// members.
	roster := &veil.Roster{
		Clocked: veil.Clocked{Context: accepts[0], Accepts: accepts, OnClockSkew: onSkew},
		Members: s.members,
	}
	if !s.cfg.ObfsRequireMemberKey {
		roster.Anonymous = &veil.Clocked{Context: accepts[0], Accepts: accepts, OnClockSkew: onSkew}
	}
	return roster
}

// enabledTransports lists the transports this server actually listens on, in
// the order they are started.
func (s *Server) enabledTransports() []string {
	transports := []string{TransportPlain}
	if s.cfg.ObfsEnabled {
		transports = append(transports, TransportObfs)
	}
	if s.cfg.WSEnabled {
		transports = append(transports, TransportWS)
	}
	return transports
}

// transportSummary renders the startup line: every transport is named, and the
// ones that are off say so rather than being absent.
func transportSummary(cfg Config) string {
	parts := []string{TransportPlain + ":" + cfg.Port}

	if cfg.ObfsEnabled {
		parts = append(parts, TransportObfs+":"+cfg.ObfsPort)
	} else {
		parts = append(parts, TransportObfs+":off")
	}

	switch {
	case !cfg.WSEnabled:
		parts = append(parts, TransportWS+":off")
	case cfg.WSAddr != "":
		parts = append(parts, TransportWS+":"+cfg.WSAddr+cfg.WSPath)
	default:
		parts = append(parts, TransportWS+":443"+cfg.WSPath)
	}

	return strings.Join(parts, ", ")
}

// listenAddr is where a listener on port binds: LISTEN_IP, or every address
// when it is empty (net.JoinHostPort gives ":port" then).
func (s *Server) listenAddr(port string) string { return net.JoinHostPort(s.cfg.ListenIP, port) }

// Stop shuts the server down and returns when it has actually stopped:
// listeners closed, live connections closed, connection handlers finished and
// the traffic counters written to USERS_FILE.
//
// Start also performs this cleanup on cancellation or failure. Stop is safe
// to call concurrently, repeatedly, and after Start has already returned.
// Before Start has begun there is no run to cancel; pass a cancellable parent
// context when scheduling startup itself must be cancellable.
//
// Live sessions are closed rather than waited for: a tunnelled session can
// last hours, and waiting for one is not a shutdown.
func (s *Server) Stop() error {
	s.lifeMu.Lock()
	run := s.run
	s.lifeMu.Unlock()
	if run == nil {
		return nil
	}
	run.cancel()
	<-run.done
	return run.stopErr
}

func (s *Server) unregisterRunMetrics() {
	// The gauge's callback holds the session registry. Leaving it registered
	// keeps a stopped server's registry alive and reporting zeroes into the
	// meter of whatever starts next in the same process.
	if s.sessionGauge != nil {
		_ = s.sessionGauge.Unregister()
		s.sessionGauge = nil
	}
	if s.udpMetrics != nil {
		_ = s.udpMetrics.Unregister()
		s.udpMetrics = nil
	}
}

// shutdownListeners closes every listener the run
// started and waits for the goroutines serving them. Closing a listener stops
// new connections; the cancelled context is what reaches the established
// ones, and the wait is what makes "stopped" mean stopped rather than
// "stopping". Idempotent: Close is once-only per listener and a second Wait
// on a drained group returns at once. Only the Start owner calls it, after
// cancelling its run, before flushing counters and closing the journal.
func (s *Server) shutdownListeners() {
	s.mu.Lock()
	nativeMetrics := s.nativeMetrics
	s.nativeMetrics = nil
	s.mu.Unlock()
	if nativeMetrics != nil {
		_ = nativeMetrics.Unregister()
	}
	if h := s.nativeHub.Load(); h != nil {
		_ = h.Close()
	}
	for _, p := range s.allPipelines() {
		_ = p.Close()
	}
	s.wg.Wait()
}

// WSAddr returns the network address of the WebSocket stealth listener,
// or empty string if WS is not enabled.
func (s *Server) WSAddr() string {
	s.mu.Lock()
	wsL := s.wsListen
	s.mu.Unlock()
	if wsL != nil {
		return wsL.Addr().String()
	}
	return ""
}
