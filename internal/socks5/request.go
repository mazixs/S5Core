package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
	"github.com/mazixs/S5Core/internal/session"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	UDPTunnelCommand = uint8(0x83) // Custom custom command for UDP-over-TCP tunneling
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	errUnrecognizedAddrType = fmt.Errorf("unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if len(a.IP) != 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// Datagram marks a request that is not a connection setup but one
	// datagram of an established UDP association, put to the rules on its
	// own. DestAddr is then the destination that datagram names, which is
	// the only place a UDP destination appears at all: the address in the
	// ASSOCIATE request that set the association up describes the client
	// side of it and says nothing about where the client will send.
	//
	// A RuleSet that only looks at Command sees no difference and needs
	// none. One that looks at DestAddr has to know which of the two
	// questions it is being asked, or it ends up matching a destination
	// pattern against the client's own address (F02 in
	// docs/reports/code-quality-audit-2026-09-20.md).
	Datagram bool
	// attemptDeadline is when reaching the destination has to have happened.
	// Resolving the name and dialing share it, because the client is waiting
	// for the same reply throughout both, and it is zero when the session has
	// no dial budget.
	attemptDeadline time.Time
	dialCandidates  []dialCandidate
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
	// session is the connection's state machine (plan task Ф6-1), nil when
	// the connection did not come through a listener pipeline. Every method
	// on a nil session is a no-op, so the handlers below do not check.
	session *session.Session
}

// conn is what answering a request needs: somewhere to write the reply and
// the address it came from. It is deliberately narrower than net.Conn, so a
// handler can be driven from a buffer in a test.
type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

// socketOf hands back the client's socket. The UDP paths need one: an
// association outlives the request that opened it, holds the client's TCP
// connection as its lifetime marker, and takes that connection's local
// address and its deadlines.
//
// They used to assert it three times without checking, which turns a caller
// that passes anything else - a test double, the next wrapper somebody adds
// - into a panic in the middle of an association rather than an error at its
// start. The CONNECT path, which wants a socket only if there is one, keeps
// asking with a comma-ok of its own.
func socketOf(c conn) (net.Conn, error) {
	nc, ok := c.(net.Conn)
	if !ok {
		return nil, fmt.Errorf("socks: a UDP association needs the client's socket, got %T", c)
	}
	return nc, nil
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(conn io.Reader) (*Request, error) {
	// Read the version byte
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, connFailure("request", "header_read", err)
	}

	// Ensure we are compatible
	if header[0] != Socks5Version {
		return nil, protocolFailure("request", "header_read", fmt.Errorf("unsupported command version: %v", header[0]))
	}

	// Read in the destination address
	dest, err := readAddrSpec(conn)
	if err != nil {
		if errors.Is(err, errUnrecognizedAddrType) {
			return nil, protocolFailure("request", "address_read", err)
		}
		return nil, connFailure("request", "address_read", err)
	}

	request := &Request{
		Version:  Socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  conn,
	}

	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(ctx context.Context, req *Request, conn conn) error {
	// The rules are checked before the name is resolved. They used to be
	// checked inside each command handler, after Resolve had already run, so a
	// forbidden destination was still looked up: the DNS query went out, the
	// resolver logged it, and an observer watching the server learned what the
	// client had asked for. A destination that is not allowed should leave no
	// trace outside this process.
	ctx, allowed := s.config.Rules.Allow(ctx, req)
	if !allowed {
		failure := &ConnError{Stage: "request", Op: "rules", Kind: FailurePolicy, Err: errors.New("destination blocked by rules")}
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return errors.Join(failure, connFailure("request", "reply_write", err))
		}
		return failure
	}

	// A CONNECT is dialing from here on: resolving the name is the first
	// step of reaching the destination, and a client waiting for the reply
	// is waiting for this too. The other commands have nothing to dial.
	if req.Command == ConnectCommand {
		req.session.Enter(session.Dialing)
	}

	// Reaching the destination gets one budget, and looking the name up is
	// the first part of reaching it. The lookup used to run on the
	// connection's own context, which has no deadline of its own: a resolver
	// that never answered held the handler past every timeout the session
	// has, while the client sat waiting for a reply nobody was working on
	// (audit finding F12). The dial below now starts from what the lookup
	// left of the same budget.
	resolveCtx := ctx
	if budget := req.session.SLA().Dial; budget > 0 {
		req.attemptDeadline = time.Now().Add(budget)
		var cancelAttempt context.CancelFunc
		resolveCtx, cancelAttempt = context.WithDeadline(ctx, req.attemptDeadline)
		defer cancelAttempt()
	}

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		dnsPhase := s.startPhase(PhaseDNS)
		var ctx_ context.Context
		var addr net.IP
		var ips []net.IP
		var err error
		if multi, ok := s.config.Resolver.(MultiNameResolver); ok && req.Command == ConnectCommand {
			ctx_, ips, err = multi.ResolveAll(resolveCtx, dest.FQDN)
			if err == nil {
				ips = interleaveIPs(ips)
			}
			if err == nil && len(ips) == 0 {
				err = errors.New("resolver returned no addresses")
			}
			if err == nil {
				addr = ips[0]
			}
		} else {
			ctx_, addr, err = s.config.Resolver.Resolve(resolveCtx, dest.FQDN)
		}
		dnsPhase.end(err == nil)
		if err != nil {
			failure := connFailure("dial", "resolve", err)
			if replyErr := sendReply(conn, hostUnreachable, nil); replyErr != nil {
				return errors.Join(failure, connFailure("request", "reply_write", replyErr))
			}
			return failure
		}
		// A resolver may hand back a context carrying values the rest of the
		// request should see - that is what the interface returns one for.
		// What it must not hand back is the lookup's deadline: everything
		// after this, the relay included, lives as long as the connection
		// does. keepValues takes the one and leaves the other.
		ctx = keepValues(ctx, ctx_)
		dest.IP = addr
		// The rewriter retains sole control when configured: its single
		// result must never fall back to a pre-rewrite destination.
		if s.config.Rewriter == nil && len(ips) > 0 {
			for _, ip := range ips {
				candidateAddr := *dest
				candidateAddr.IP = append(net.IP(nil), ip...)
				numericAddr := candidateAddr.Address()
				candidateReq := *req
				candidateReq.DestAddr = &candidateAddr
				candidateCtx, allowed := s.config.Rules.Allow(ctx, &candidateReq)
				if allowed {
					req.dialCandidates = append(req.dialCandidates, dialCandidate{ctx: keepValues(ctx, candidateCtx), addr: numericAddr})
				}
			}
			if len(req.dialCandidates) == 0 {
				failure := &ConnError{Stage: "request", Op: "rules", Kind: FailurePolicy, Err: errors.New("resolved addresses blocked by rules")}
				if err := sendReply(conn, ruleFailure, nil); err != nil {
					return errors.Join(failure, err)
				}
				return failure
			}
		}
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}
	if req.realDestAddr == nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return connFailure("request", "reply_write", err)
		}
		return fmt.Errorf("rewrite returned nil address")
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	case UDPTunnelCommand:
		return s.handleUDPTcpmux(ctx, conn, req)
	default:
		failure := protocolFailure("request", "command", fmt.Errorf("unsupported command: %v", req.Command))
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return errors.Join(failure, connFailure("request", "reply_write", err))
		}
		return failure
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn conn, req *Request) error {
	// The rules have already been applied in handleRequest, before the name
	// was resolved.
	sess := req.session

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, net_, addr)
		}
	}
	// One attempt gets the session's dial budget. Without it the attempt
	// runs on the operating system's own timeout, which is over two minutes
	// on Linux - and every one of those minutes the client sits waiting for
	// its reply, which is the picture the bug report drew.
	//
	// The deadline is the one handleRequest set before resolving the name,
	// not a fresh budget: a slow lookup and a slow dial are the same wait
	// seen by the client, and giving each the full budget doubled it.
	dialCtx := ctx
	if !req.attemptDeadline.IsZero() {
		var cancelDial context.CancelFunc
		dialCtx, cancelDial = context.WithDeadline(ctx, req.attemptDeadline)
		defer cancelDial()
	}
	dialPhase := s.startPhase(PhaseDial)
	candidates := req.dialCandidates
	if len(candidates) == 0 {
		candidates = []dialCandidate{{ctx: ctx, addr: req.realDestAddr.Address()}}
	}
	target, err := dialResolved(dialCtx, dial, candidates)
	dialPhase.end(err == nil)
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		failure := connFailure("dial", "connect", err)
		if replyErr := sendReply(conn, resp, nil); replyErr != nil {
			return errors.Join(failure, connFailure("request", "reply_write", replyErr))
		}
		return failure
	}
	defer func() {
		_ = target.Close()
	}()

	// Send success
	local, ok := target.LocalAddr().(*net.TCPAddr)
	if !ok {
		local = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return connFailure("request", "reply_write", err)
	}

	// The handshake is over. From here the connection is a relay: the
	// transport asks the session for its deadlines, and the relay idle
	// timeout replaces the handshake budget.
	sess.Enter(session.Relay)

	// The wait for the destination's first byte starts once the client has its
	// success reply: from here on, any delay is the destination's or ours.
	var targetSrc io.Reader = target
	if fb := s.startPhase(PhaseFirstByte); fb != nil {
		targetSrc = &firstByteReader{Reader: target, timer: fb}
		defer fb.end(false)
	}

	// Extract username for per-user traffic tracking
	username := extractUsername(req)

	// Only the destination side is observed here. The client side is closed
	// through the transport stack, which is the only place that knows whether
	// the client arrived over plain TCP, obfs or a WebSocket - and that
	// difference is exactly what is worth counting.
	var targetWriteOnce sync.Once
	closeTargetWrite := func() {
		targetWriteOnce.Do(func() { relay.HalfClose(target, s.halfCloseObserver()) })
	}
	closeClientWrite := func() { relay.HalfClose(conn, nil) }

	// Start proxying
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Resolved once per connection: the relay asks a closure, not the store.
	var status func() SessionStatus
	if s.config.SessionStatus != nil && username != "" {
		status = func() SessionStatus { return s.config.SessionStatus(username) }
	}

	// Resolved once per connection, and only if there is something to
	// resolve: an unmetered server, or a user the store no longer knows, gets
	// no counter. That says nothing about whether the account is asked - the
	// relay asks Status regardless, which is the point of F01.
	var counter *atomic.Int64
	if s.config.TrafficCounter != nil && username != "" {
		counter = s.config.TrafficCounter(username)
	}

	// exhaust is the one place the account region reaches the protocol
	// region. The account can no longer transfer; whether the relay ends
	// here or drains depends on the session's grace budget. During a drain
	// the destination is told that no more requests come and gets until the
	// end of the grace to answer the ones it has, nothing more goes towards
	// it, and what it sends still reaches the client. Without a grace budget
	// - or without a session, as in tests and SDK use - both halves end at
	// once, which is the historical behaviour.
	//
	// It answers whether the calling half keeps copying: only the half
	// towards the client does, and only during a drain.
	exhaust := func(toClient bool) func(SessionStatus) bool {
		return func(st SessionStatus) bool {
			if sess.Exhaust(st.AccountState()) && sess.InGrace() {
				closeTargetWrite()
				if end, ok := sess.GraceDeadline(); ok {
					_ = target.SetReadDeadline(end)
				}
			}
			return toClient && sess.InGrace()
		}
	}

	toDestination := &relay.Half{
		Dst: target, Src: req.bufConn,
		Counter: counter, Status: status, Exhaust: exhaust(false),
		CloseDst: closeTargetWrite,
	}
	toClient := &relay.Half{
		Dst: conn, Src: targetSrc,
		Counter: counter, Status: status, Exhaust: exhaust(true),
		CloseDst: closeClientWrite,
	}

	results := make(chan relay.Result, 2)
	go func() { results <- relay.Result{ToDestination: true, Err: toDestination.Run()} }()
	go func() { results <- relay.Result{Err: toClient.Run()} }()

	closeBoth := func() {
		cancel()
		// Force-close connections to unblock the other goroutine
		_ = target.Close()
		if nc, ok := conn.(net.Conn); ok {
			_ = nc.Close()
		}
	}

	// Wait for both halves. A half that ends cleanly - its source sent EOF -
	// leaves the other running: that is the half-closed state, and it is how
	// a destination gets to finish its answer after the client is done
	// asking. A half that fails takes the other down with it.
	var firstErr error
	for pending := 2; pending > 0; {
		select {
		case r := <-results:
			pending--
			switch {
			case sess.InGrace():
				// The account ended the session and the drain is running.
				// The half towards the destination is expected to end - its
				// side of the destination is closed - and the end of the
				// drain is the end of the session.
				if firstErr == nil {
					firstErr = ErrSessionNotAllowed
				}
				if !r.ToDestination {
					closeBoth()
				}
			case r.Err != nil:
				if firstErr == nil {
					firstErr = r.Err
				}
				closeBoth()
			default:
				sess.Enter(session.HalfClosed)
			}
		case <-proxyCtx.Done():
			// The relay was ended by the context rather than by either peer:
			// the server is stopping, or the caller gave up. Both sides are
			// closed so the halves stop copying, and then they are waited
			// for.
			//
			// This branch used to be empty, which meant returning while both
			// halves were still running. The destination stayed open until
			// the deferred close ran - and the halves kept copying through a
			// connection the caller was closing, so a shutdown raced every
			// live relay instead of ending it.
			if firstErr == nil {
				firstErr = proxyCtx.Err()
			}
			closeBoth()
			for ; pending > 0; pending-- {
				<-results
			}
		}
	}
	return connFailure("relay", "copy", firstErr)
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, conn conn, req *Request) error {
	// Rules were applied in handleRequest, before any name was resolved.

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return connFailure("request", "reply_write", err)
	}
	return nil
}

// readAddrSpec is used to read AddrSpec.
// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	var addrType [1]byte
	if _, err := io.ReadFull(r, addrType[:]); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr[:])

	case ipv6Address:
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr[:])

	case fqdnAddress:
		if _, err := io.ReadFull(r, addrType[:]); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, errUnrecognizedAddrType
	}

	// Read the port
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("failed to format address: %v", addr)
	}

	msg := make([]byte, 0, 6+len(addrBody))
	msg = append(msg, Socks5Version, resp, 0, addrType)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))

	// Send the message
	_, err := w.Write(msg)
	return err
}

// extractUsername returns the authenticated username from the request, if any.
func extractUsername(req *Request) string {
	if req.AuthContext != nil && req.AuthContext.Payload != nil {
		return req.AuthContext.Payload["Username"]
	}
	return ""
}
