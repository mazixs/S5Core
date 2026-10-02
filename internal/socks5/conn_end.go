package socks5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
)

// The outcome of a connection, a closed set: a journal and a metric label
// both take it (docs/design/observability-policy.md).
const (
	ResultOK              = "ok"
	ResultAuthFailed      = "auth_failed"
	ResultRulesDenied     = "rules_denied"
	ResultPrivateDest     = "private_dest"
	ResultResolveFailed   = "resolve_failed"
	ResultDialTimeout     = "dial_timeout"
	ResultDialRefused     = "dial_refused"
	ResultDialUnreachable = "dial_unreachable"
	ResultReplyFailed     = "reply_failed"
	ResultAccount         = "account"
	ResultShutdown        = "shutdown"
	ResultError           = "error"
)

// Results is the closed set of ConnEnd.Result.
func Results() []string {
	return []string{ResultOK, ResultAuthFailed, ResultRulesDenied, ResultPrivateDest, ResultResolveFailed,
		ResultDialTimeout, ResultDialRefused, ResultDialUnreachable, ResultReplyFailed,
		ResultAccount, ResultShutdown, ResultError}
}

// Who ended a relayed CONNECT, a closed set. An association says it with the
// EndedBy names instead.
const (
	ClosedByClient        = "client"
	ClosedByTarget        = "target"
	ClosedByServerTimeout = "server_timeout"
	ClosedByAccount       = "account"
	ClosedByShutdown      = "shutdown"
	ClosedByReset         = "reset"
)

// ClosedBys is the closed set of ConnEnd.ClosedBy on a CONNECT.
func ClosedBys() []string {
	return []string{ClosedByClient, ClosedByTarget, ClosedByServerTimeout, ClosedByAccount, ClosedByShutdown, ClosedByReset}
}

// The command a connection carried, as the journal names it.
const (
	CmdConnect = "connect"
	CmdBind    = "bind"
)

// CmdUnknown is a command this server does not know.
const CmdUnknown = "unknown"

// Commands is the closed set of ConnEnd.Command.
func Commands() []string {
	return []string{CmdConnect, CmdBind, AssociationPlain, AssociationTunnel, AssociationNative, CmdUnknown}
}

func commandName(cmd uint8) string {
	switch cmd {
	case ConnectCommand:
		return CmdConnect
	case BindCommand:
		return CmdBind
	case AssociateCommand:
		return AssociationPlain
	case UDPTunnelCommand:
		return AssociationTunnel
	case UDPNativeCommand:
		return AssociationNative
	}
	return CmdUnknown
}

func isAssociation(cmd uint8) bool {
	return cmd == AssociateCommand || cmd == UDPTunnelCommand || cmd == UDPNativeCommand
}

// How the account was established.
const (
	AuthKey      = "key"
	AuthPassword = "password"
	AuthNone     = "none"
)

// AccountUnknown stands for a login the server refused. The name offered is
// never kept: a scanner would write what it likes into the journal, and a user
// who typed the password into the name field would write the password.
const AccountUnknown = "unknown"

// The outcome of one address of a dial, a closed set.
const (
	DialOK          = "ok"
	DialOKBackup    = "ok_backup"
	DialTimeout     = "timeout"
	DialRefused     = "refused"
	DialUnreachable = "unreachable"
	DialNoRoute     = "no_route"
	DialCanceled    = "canceled"
)

// DialOutcomes is the closed set of DialOutcome.Outcome.
func DialOutcomes() []string {
	return []string{DialOK, DialOKBackup, DialTimeout, DialRefused, DialUnreachable, DialNoRoute, DialCanceled}
}

// DialOutcome is how one address of a dial ended.
type DialOutcome struct {
	V6      bool
	Outcome string
}

// ConnEnd is what the server learned about one connection, handed to
// Config.OnConnEnd once, after the connection is closed and every goroutine
// it started has returned. It carries no client address and no host name;
// the destination is the address dialled, and whoever records it decides
// how much of it to keep.
type ConnEnd struct {
	// Spoke is false for a peer that never sent the SOCKS5 version byte: a
	// probe, not a session.
	Spoke bool
	// Command is CmdConnect, CmdBind or an Association kind; empty when the
	// request was never read.
	Command  string
	Account  string
	Auth     string
	Result   string
	Stage    string
	ClosedBy string

	// Dst is the address dialled, or for an association its first target.
	// DstName says the client asked for a name rather than an address.
	Dst     netip.AddrPort
	DstName bool

	DialTime      time.Duration
	DialTries     int
	DialBackups   int
	DialBackupWon bool
	DialOutcomes  []DialOutcome
	FirstByte     time.Duration

	// Up is what went to the destination, Down what came back to the client.
	Up, Down int64
	// The datagrams of an association, both ways.
	DatagramsUp, DatagramsDown int64
	// Rotations of the egress socket of a UDP tunnel, and whether a target
	// ever answered on it.
	Rotations int64
	Answered  bool
	// What a native association carried by the native path, each way; the
	// rest of its datagrams went by the stream. PathMoves is how often the
	// answers left the native path for the stream, TunnelDrops the frames
	// the stream's writer did not write.
	NativeUp, NativeDown int64
	PathMoves            int64
	TunnelDrops          int64

	Started  time.Time
	Duration time.Duration

	dgram     assocTotals
	native    nativeTotals
	targetSet atomic.Bool
}

// nativeTotals counts datagrams on the native path as they pass: a datagram
// is one atomic add here, not a lock.
type nativeTotals struct {
	up, down atomic.Int64
}

func (e *ConnEnd) nativeDatagram(down bool) {
	if e == nil {
		return
	}
	if down {
		e.native.down.Add(1)
		return
	}
	e.native.up.Add(1)
}

// pathEnded records what the stream and the answers' path did over the
// association.
func (e *ConnEnd) pathEnded(moves int64, drops uint64) {
	if e == nil {
		return
	}
	e.PathMoves = moves
	e.TunnelDrops = int64(drops)
}

// assocTotals is filled by the meters of an association as they flush, so a
// datagram costs nothing here.
type assocTotals struct {
	up, down, upN, downN atomic.Int64
}

func (e *ConnEnd) addDatagrams(up, down, upN, downN int64) {
	if e == nil {
		return
	}
	e.dgram.up.Add(up)
	e.dgram.down.Add(down)
	e.dgram.upN.Add(upN)
	e.dgram.downN.Add(downN)
}

// target records the first destination of an association.
func (e *ConnEnd) target(dest netip.AddrPort) {
	if e == nil || e.targetSet.Load() || !e.targetSet.CompareAndSwap(false, true) {
		return
	}
	e.Dst = dest
}

func (e *ConnEnd) authenticated(a *AuthContext) {
	if e == nil || a == nil {
		return
	}
	name := a.Payload["Username"]
	switch {
	case a.Method == UserPassAuth:
		e.Auth, e.Account = AuthPassword, name
	case name != "":
		e.Auth, e.Account = AuthKey, name
	default:
		e.Auth = AuthNone
	}
}

// associationEnded fills what an association adds. reason is one of the
// EndedBy names.
func (e *ConnEnd) associationEnded(kind, reason string, egress *rotatingUDP) {
	if e == nil {
		return
	}
	e.Command = kind
	e.ClosedBy = reason
	switch reason {
	case EndedByAccount:
		e.Result = ResultAccount
	case EndedByShutdown:
		e.Result = ResultShutdown
	case EndedByError:
		e.Result = ResultError
	default:
		e.Result = ResultOK
	}
	if egress != nil {
		e.Rotations = egress.rotations()
		e.Answered = egress.recvCount() > 0
	}
}

// How the egress rotations of an association ended, a closed set.
const (
	RotationAnswered = "answered"
	RotationGaveUp   = "gave_up"
	RotationClosed   = "closed"
)

// RotationOutcomes is the closed set of RotationOutcome.
func RotationOutcomes() []string { return []string{RotationAnswered, RotationGaveUp, RotationClosed} }

// RotationOutcome says how an association that rotated its egress socket
// ended: a target answered, the draws ran out, or it closed before either.
// Empty when it never rotated.
func (e *ConnEnd) RotationOutcome() string {
	switch {
	case e.Rotations == 0:
		return ""
	case e.Answered:
		return RotationAnswered
	case e.Rotations >= udpRotateMax:
		return RotationGaveUp
	}
	return RotationClosed
}

// End is the one cause of the end, the same field on a CONNECT and on an
// association: who closed it once the relay ran, otherwise the outcome of the
// setup that failed.
func (e *ConnEnd) End() string {
	if e.ClosedBy != "" {
		return e.ClosedBy
	}
	return e.Result
}

// Kind is the metric's coarse name for Command: connect, udp, bind or none.
func (e *ConnEnd) Kind() string {
	switch e.Command {
	case CmdConnect:
		return KindConnect
	case CmdBind:
		return KindBind
	case AssociationPlain, AssociationTunnel, AssociationNative:
		return KindUDP
	}
	return KindNone
}

// The closed set of ConnEnd.Kind.
const (
	KindConnect = "connect"
	KindUDP     = "udp"
	KindBind    = "bind"
	KindNone    = "none"
)

// Kinds is the closed set of ConnEnd.Kind.
func Kinds() []string { return []string{KindConnect, KindUDP, KindBind, KindNone} }

// finish closes the record once the handler has returned with err.
func (e *ConnEnd) finish(err error) {
	e.Duration = time.Since(e.Started)
	e.Up += e.dgram.up.Load()
	e.Down += e.dgram.down.Load()
	e.DatagramsUp = e.dgram.upN.Load()
	e.DatagramsDown = e.dgram.downN.Load()
	e.NativeUp = e.native.up.Load()
	e.NativeDown = e.native.down.Load()
	if e.Result != "" {
		return
	}
	e.Result, e.Stage = connResult(err)
	if e.Result == ResultAuthFailed {
		e.Account, e.Auth = AccountUnknown, ""
	}
}

// connResult names the outcome of a connection from the error its handler
// returned. Only a failure gets a stage.
func connResult(err error) (result, stage string) {
	if err == nil {
		return ResultOK, ""
	}
	var ce *ConnError
	if !errors.As(err, &ce) {
		return ResultError, ""
	}
	switch ce.Stage {
	case "greeting", "auth":
		if ce.Kind == FailureAuth {
			return ResultAuthFailed, ce.Stage
		}
	case "request":
		switch ce.Op {
		case "rules":
			return ResultRulesDenied, ce.Stage
		case "private_dest":
			return ResultPrivateDest, ce.Stage
		case "reply_write":
			return ResultReplyFailed, ce.Stage
		}
	case "dial":
		if ce.Op == "resolve" {
			return ResultResolveFailed, ce.Stage
		}
		switch dialOutcome(ce.Err) {
		case DialCanceled:
			return ResultShutdown, ce.Stage
		case DialRefused:
			return ResultDialRefused, ce.Stage
		case DialUnreachable, DialNoRoute:
			return ResultDialUnreachable, ce.Stage
		case DialTimeout:
			return ResultDialTimeout, ce.Stage
		}
	case "relay":
		switch ce.Kind {
		case FailureCanceled:
			return ResultShutdown, ""
		case FailurePolicy:
			return ResultAccount, ""
		}
		return ResultOK, ""
	}
	return ResultError, ce.Stage
}

// dialOutcome classifies the error of a failed dial attempt.
func dialOutcome(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return DialCanceled
	case refused(err):
		return DialRefused
	case noRoute(err):
		return DialNoRoute
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EHOSTDOWN):
		return DialUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return DialTimeout
	}
	return DialUnreachable
}

// relayClosedBy names who ended a relay from the first half to end.
func relayClosedBy(r relay.Result, grace, canceled bool) string {
	var ne net.Error
	switch {
	case grace, errors.Is(r.Err, ErrSessionNotAllowed):
		return ClosedByAccount
	case canceled, errors.Is(r.Err, context.Canceled):
		return ClosedByShutdown
	case r.Err == nil && r.ToDestination:
		return ClosedByClient
	case r.Err == nil:
		return ClosedByTarget
	case errors.As(r.Err, &ne) && ne.Timeout():
		return ClosedByServerTimeout
	}
	return ClosedByReset
}

// dialRecorder watches the sockets of one dial through the dial function it
// wraps. dialResolved does not wait for the attempts it abandons, so what is
// known is read once, as it returns.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []dialAddr
}

type dialAddr struct {
	addr    string
	sockets int
	err     error
	// winners are the sockets that connected, by their place in the order
	// this address opened them: 1 is the first attempt.
	winners []dialSocket
}

type dialSocket struct {
	nth  int
	conn net.Conn
}

func (d *dialRecorder) wrap(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d.mu.Lock()
		i := d.index(addr)
		d.addrs[i].sockets++
		nth := d.addrs[i].sockets
		d.mu.Unlock()
		c, err := dial(ctx, network, addr)
		d.mu.Lock()
		switch {
		case err != nil:
			if d.addrs[i].err == nil {
				d.addrs[i].err = err
			}
		case c != nil:
			d.addrs[i].winners = append(d.addrs[i].winners, dialSocket{nth, c})
		}
		d.mu.Unlock()
		return c, err
	}
}

func (d *dialRecorder) index(addr string) int {
	for i := range d.addrs {
		if d.addrs[i].addr == addr {
			return i
		}
	}
	d.addrs = append(d.addrs, dialAddr{addr: addr})
	return len(d.addrs) - 1
}

// settle writes what the dial did into e: target is what dialResolved
// returned, fallback the address named when it returned none.
func (d *dialRecorder) settle(e *ConnEnd, target net.Conn, fallback string, took time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e.DialTime = took
	e.DialTries = len(d.addrs)
	dst := fallback
	if len(d.addrs) > 0 && target == nil {
		dst = d.addrs[0].addr
	}
	for i := range d.addrs {
		a := &d.addrs[i]
		e.DialBackups += a.sockets - 1
		outcome := ""
		for _, w := range a.winners {
			if target != nil && w.conn == target {
				dst = a.addr
				outcome = DialOK
				if w.nth > 1 {
					outcome = DialOKBackup
					e.DialBackupWon = true
				}
			}
		}
		if outcome == "" {
			switch {
			case a.err != nil:
				outcome = dialOutcome(a.err)
			case target != nil:
				outcome = DialCanceled
			default:
				outcome = DialTimeout
			}
		}
		if ap, err := netip.ParseAddrPort(a.addr); err == nil {
			e.DialOutcomes = append(e.DialOutcomes, DialOutcome{V6: ap.Addr().Unmap().Is6(), Outcome: outcome})
		}
	}
	if ap, err := netip.ParseAddrPort(dst); err == nil {
		e.Dst = ap
	}
}
