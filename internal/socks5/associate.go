package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/internal/udpbuf"
)

// handleAssociate implements the standard RFC 1928 UDP ASSOCIATE.
// The client connects via TCP to request a UDP relay.
// The server opens a UDP socket and tells the client its IP/Port.
// The client then sends UDP packets to that socket.
//
// Two sockets, not one. The port advertised to the client used to be the same
// port the relay sent from, so every datagram that arrived had to be sorted by
// its source address: a command from the client when the address matched, a
// reply from the internet when it did not. That guess was wrong in both
// directions. Anything arriving from an address that was not the client -
// which, on a port reachable from the internet, is anything at all - went to
// the client as though a target had answered, so any host that found the port
// could inject datagrams into the client's stream. And a client that asked to
// reach a service on its own address had the service's replies parsed as
// commands. Separating the sockets replaces the guess with the socket the
// datagram arrived on, which nothing off-path can forge (plan task Ф6-5).
func (s *Server) handleAssociate(ctx context.Context, conn conn, req *Request) error {
	// handleRequest asked the rules about the command. Where the datagrams
	// may go is a different question, asked per datagram in allowDatagram.

	// The client's socket, asked for once and named in the refusal if it is
	// not there at all.
	client, err := socketOf(conn)
	if err != nil {
		if replyErr := sendReply(conn, serverFailure, nil); replyErr != nil {
			return fmt.Errorf("failed to send reply: %w", replyErr)
		}
		return err
	}

	a := &plainAssociation{
		s:   s,
		req: req,
		// The account is resolved once, here, and shared by both directions:
		// where its traffic is counted, and whether it may still transfer.
		acct: s.udpAccountFor(req),
	}

	if err := a.bind(conn, client); err != nil {
		return err
	}
	defer func() { _ = a.clientConn.Close() }()
	defer func() { _ = a.targetConn.Close() }()

	// We only accept packets from the client's registered IP (weak security as per RFC)
	a.clientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	assocCtx, cancel := context.WithCancel(ctx)
	a.errCh = make(chan error, 3)
	a.done = make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(3)
	defer func() {
		cancel()
		_ = client.SetDeadline(time.Now())
		_ = a.clientConn.Close()
		_ = a.targetConn.Close()
		workers.Wait()
	}()

	// The TCP connection is now only a lifetime marker for the association: it
	// carries no bytes and is expected to stay silent. As a tunnel it lives
	// under no idle timeout (internal/session Kind); clearing the deadline
	// the handshake left behind is still needed, because the session only
	// stops arming a new one - it cannot retract one already set.
	req.session.Become(session.Tunnel)
	req.session.Enter(session.Relay)
	_ = client.SetDeadline(time.Time{})

	// TCP Connection monitor - if TCP closes, all UDP goroutines must terminate.
	// It reads through the handshake buffer, not the socket: a client that
	// sent anything alongside its request left it there, and a read straight
	// from the socket would wait for a byte that has already arrived (plan
	// task Ф6-5).
	var closed error
	go func() {
		defer workers.Done()
		var b [1]byte
		_, closed = req.bufConn.Read(b[:])
		close(a.done)
		// Force the blocking UDP reads to unblock
		_ = a.clientConn.Close()
		_ = a.targetConn.Close()
	}()

	go func() {
		defer workers.Done()
		a.fromClient(ctx, assocCtx)
	}()
	go func() {
		defer workers.Done()
		a.fromTargets()
	}()

	// Wait for TCP close, a relay failure, or server shutdown. A closed TCP
	// connection is the association's normal end whatever closed it, but a
	// reset is still worth telling from a close.
	var end error
	select {
	case <-ctx.Done():
		end = ctx.Err()
		s.associationEnded(req, AssociationPlain, end, nil)
	case <-a.done:
		s.associationEnded(req, AssociationPlain, closed, nil)
	case end = <-a.errCh:
		s.associationEnded(req, AssociationPlain, end, nil)
	}
	return end
}

// plainAssociation is one RFC 1928 UDP ASSOCIATE: the socket the client talks
// to, the socket the targets talk to, and what both directions share.
type plainAssociation struct {
	s    *Server
	req  *Request
	acct *udpAccount

	clientConn *net.UDPConn
	targetConn *net.UDPConn
	clientIP   string
	// clientAddr is written by the client-facing goroutine and read by the
	// target-facing one.
	clientAddr atomic.Pointer[net.UDPAddr]

	done  chan struct{}
	errCh chan error
}

// bind opens both sockets and answers the client with the address of its own.
// On failure it answers with serverFailure and closes what it opened.
func (a *plainAssociation) bind(conn conn, client net.Conn) error {
	// The socket the client talks to. Its address is what the reply carries.
	bindAddr := &net.UDPAddr{IP: a.s.config.BindIP, Port: 0}
	if bindAddr.IP == nil {
		bindAddr.IP = net.IPv4zero
	}
	clientConn, err := udpbuf.ListenUDP("udp", bindAddr)
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind UDP port: %w", err)
	}

	// The socket the internet talks to. It takes the same local address, so
	// an operator who pinned BIND_IP to one interface still has every
	// datagram leave through it, and a port of its own, so the address the
	// client was handed is not the address targets get to see.
	targetConn, err := udpbuf.ListenUDP("udp", &net.UDPAddr{IP: bindAddr.IP, Port: 0})
	if err != nil {
		_ = clientConn.Close()
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind UDP egress port: %w", err)
	}
	a.clientConn, a.targetConn = clientConn, targetConn

	// Tell the client where to send UDP packets
	localAddr := clientConn.LocalAddr().(*net.UDPAddr)
	bindSpec := AddrSpec{IP: localAddr.IP, Port: localAddr.Port}

	// Some clients expect our public IP if we bound to 0.0.0.0
	if bindSpec.IP.IsUnspecified() {
		if tcpLocal, ok := client.LocalAddr().(*net.TCPAddr); ok {
			bindSpec.IP = tcpLocal.IP
		}
	}

	if err := sendReply(conn, successReply, &bindSpec); err != nil {
		_ = clientConn.Close()
		_ = targetConn.Close()
		return fmt.Errorf("failed to send reply: %w", err)
	}
	return nil
}

// fromClient relays client -> target. Everything that arrives here claims to
// be from the client, and is dropped unless it really is.
func (a *plainAssociation) fromClient(ctx, assocCtx context.Context) {
	s, req := a.s, a.req
	buf := make([]byte, 65535)
	meter := newUDPMeter(a.acct)
	question := newDatagramQuestion(req)
	dispatcher := newUDPDispatcher(assocCtx, s.datagramResolver(req.session.SLA().Dial), func(payload []byte, dest netip.AddrPort) bool {
		nw, err := a.targetConn.WriteToUDPAddrPort(payload, dest)
		if err != nil || nw <= 0 {
			return true
		}
		req.end.target(dest)
		if st := meter.inbound(nw); st != SessionAllowed {
			select {
			case a.errCh <- s.endOfAssociation(req, st):
			default:
			}
			return false
		}
		return true
	}, meter.flush)
	defer dispatcher.close()

	for {
		select {
		case <-a.done:
			return
		default:
		}

		// Set a short read deadline so we can check `done` periodically
		_ = a.clientConn.SetReadDeadline(time.Now().Add(udpPollInterval))
		n, rAddr, err := a.clientConn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-a.done:
			default:
				a.errCh <- fmt.Errorf("udp read failed: %w", err)
			}
			return
		}

		if !isClientDatagram(a.clientAddr.Load(), a.clientIP, rAddr) {
			continue
		}

		// Parse SOCKS5 UDP header
		// IMPORTANT: copy the IP out of buf before reuse
		hdrLen, err := parseUDPHeaderInto(buf[:n], &question.dest)
		if err != nil {
			s.config.Logger.Warn("socks: invalid UDP header from client", "error", err)
			continue
		}

		if !s.allowDatagram(ctx, question) {
			s.config.Logger.Debug("socks: udp datagram blocked by rules",
				"destination", question.dest.String())
			continue
		}

		// Remember client's actual UDP address (atomic store)
		addrCopy := &net.UDPAddr{
			IP:   make(net.IP, len(rAddr.IP)),
			Port: rAddr.Port,
			Zone: rAddr.Zone,
		}
		copy(addrCopy.IP, rAddr.IP)
		a.clientAddr.Store(addrCopy)

		dispatcher.submit(&question.dest, buf[hdrLen:n])
	}
}

// fromTargets relays target -> client. Nothing that arrives here is ever read
// as a command: it is a reply, and the only question is whether there is a
// client address to send it to yet.
func (a *plainAssociation) fromTargets() {
	buf := make([]byte, 65535)
	meter := newUDPMeter(a.acct)
	defer meter.flush()

	for {
		select {
		case <-a.done:
			return
		default:
		}

		_ = a.targetConn.SetReadDeadline(time.Now().Add(udpPollInterval))
		n, rAddr, err := a.targetConn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-a.done:
			default:
				a.errCh <- fmt.Errorf("udp read failed: %w", err)
			}
			return
		}

		curClient := a.clientAddr.Load()
		if curClient == nil {
			continue // Drop if we don't know the client's UDP port yet
		}

		// The header and the datagram are assembled in a pooled
		// buffer: a fresh slice per packet, sized with the payload,
		// is up to 64 KiB of garbage per datagram on a path whose
		// whole point is small packets (plan task Ф6-5).
		pktPtr := udpBufPool.Get().(*[]byte)
		pkt := AppendUDPHeaderFromAddr((*pktPtr)[:0], rAddr)
		pkt = append(pkt, buf[:n]...)

		_, werr := a.clientConn.WriteToUDP(pkt, curClient)
		udpBufPool.Put(pktPtr)
		if werr != nil {
			continue
		}
		// The payload is what the target sent; the header this server
		// put in front of it is not the client's traffic.
		if st := meter.outbound(n); st != SessionAllowed {
			a.errCh <- a.s.endOfAssociation(a.req, st)
			return
		}
	}
}

// allowDatagram asks the rule set where this one datagram is going.
//
// Both UDP paths call it, and both call it in the same place: after the
// SOCKS5 UDP header has been parsed and before anything is done with the
// address in it. That order is the point. The destination used to be taken
// from the header and resolved and sent straight away, with the rules
// consulted exactly once, for the ASSOCIATE request that opened the
// association - and the address in that request is the client's own, so it
// never described where the client would send. An allow-list of one host was
// satisfied by naming it at setup and then sending everywhere (F02 in
// docs/reports/code-quality-audit-2026-09-20.md).
//
// Checking before Resolve matters for the same reason it does for CONNECT: a
// refused name is never looked up, so the query does not leave the host and
// the name does not appear in a resolver's log.
//
// The context the rules return is dropped. A rule set may thread values
// through a connection's context; a datagram is not a connection, and
// carrying that forward would accumulate one layer per packet.
func (s *Server) allowDatagram(ctx context.Context, q *datagramQuestion) bool {
	_, allowed := s.config.Rules.Allow(ctx, &q.req)
	return allowed
}

// datagramQuestion is the Request allowDatagram puts to the rules, made once
// per association. A RuleSet is an interface, so whatever it is handed escapes,
// and a Request built per datagram was an allocation per packet. Only the
// destination changes from one datagram to the next, and the header is parsed
// straight into it. It belongs to the one goroutine that reads the
// association's datagrams, and the rules are asked synchronously, so nothing
// sees it change.
type datagramQuestion struct {
	req  Request
	dest AddrSpec
}

func newDatagramQuestion(req *Request) *datagramQuestion {
	q := &datagramQuestion{req: Request{
		Command:     req.Command,
		AuthContext: req.AuthContext,
		RemoteAddr:  req.RemoteAddr,
		Datagram:    true,
	}}
	q.req.DestAddr = &q.dest
	return q
}

// udpPollInterval is how long a UDP read waits before looking at done. It is
// the association's shutdown latency, not a timeout: nothing is dropped when
// it expires.
const udpPollInterval = 500 * time.Millisecond

// isClientDatagram reports whether a datagram that arrived on the
// client-facing socket really came from the client. Once the client has sent
// one datagram its full address is known; until then all there is to go on is
// the address its TCP connection came from, which is what RFC 1928 itself
// calls weak security.
func isClientDatagram(known *net.UDPAddr, clientIP string, from *net.UDPAddr) bool {
	if known != nil {
		return from.String() == known.String()
	}
	return from.IP.String() == clientIP
}

// udpAccount is everything an association needs to know about the account
// behind it, resolved once when the association opens: where to add its
// traffic, where to report the metrics, and whom to ask whether it may still
// transfer. It is the UDP counterpart of what handleConnect resolves for
// relay.Half, and it is resolved in the same way and for the same reason -
// per datagram, this would be a map lookup under a lock on the hot path.
type udpAccount struct {
	// counter is the account's traffic counter, or nil when there is no
	// account or no store. This is the billing path, and it is deliberately
	// the same one the TCP relay uses: quotas that count TCP but not UDP are
	// not quotas.
	counter *atomic.Int64
	// status is asked on the batch boundary whether the account may keep
	// going. Nil is a server that does not meter accounts at all.
	status func() SessionStatus
	// bytesIn and bytesOut are the metrics, and are nil when no telemetry is
	// configured. They are separate from counter on purpose: billing used to
	// run through them, so a deployment without telemetry billed nobody for
	// any UDP traffic at all, while its users.json went on claiming the quota
	// was untouched (F03 in
	// docs/reports/code-quality-audit-2026-09-20.md).
	bytesIn  func(int64)
	bytesOut func(int64)
	// end, when set, gets the association's totals on every flush.
	end *ConnEnd
}

// udpAccountFor resolves the account behind this request.
func (s *Server) udpAccountFor(req *Request) *udpAccount {
	acct := &udpAccount{
		bytesIn:  s.config.BytesAddIn,
		bytesOut: s.config.BytesAddOut,
		end:      req.end,
	}
	username := extractUsername(req)
	if username == "" {
		return acct
	}
	if s.config.TrafficCounter != nil {
		acct.counter = s.config.TrafficCounter(username)
	}
	if s.config.SessionStatus != nil {
		acct.status = func() SessionStatus { return s.config.SessionStatus(username) }
	}
	return acct
}

// udpMeter is one goroutine's share of an association's accounting: it counts
// what that goroutine relays, hands it to the account and the metrics in
// batches, and asks on the same boundary whether the account may continue.
// The per-goroutine copy is why the two directions never contend, and the
// batch is why a busy association does not touch a shared counter per
// datagram.
//
// What is counted is the payload, never the SOCKS5 UDP header this server
// adds or strips. The header is this protocol's envelope and its size depends
// on how the client spelled the destination - 10 bytes for an IPv4 address, 22
// for IPv6, 7 plus the name for an FQDN - so counting it would make the same
// transfer cost different amounts of quota for no reason the account holder
// could see. Each datagram is counted once, in the direction it travelled: a
// datagram from the client is inbound, a datagram to the client is outbound.
// It used to be counted on the way in as a whole datagram and again on the way
// out as a payload, so a client spent its quota about twice as fast as it
// transferred.
//
// Only relayed bytes count. A datagram the rules refuse never reaches a
// destination, so it never reaches the counter either.
type udpMeter struct {
	acct *udpAccount

	// in and out are the bytes not yet handed to the metrics; due is what is
	// not yet in the account's counter. They are separate sums because the
	// metrics are directional and the quota is not.
	in, out, due int64
	// inN and outN are the datagrams behind in and out.
	inN, outN int64
	// asked is when the account was last consulted.
	asked time.Time
}

func newUDPMeter(acct *udpAccount) *udpMeter {
	return &udpMeter{acct: acct, asked: time.Now()}
}

// udpMeterBatch is how much traffic accumulates before it is reported and the
// account is asked. It is the relay's flush threshold, so a UDP association
// overruns its quota by no more than a TCP connection does.
const udpMeterBatch = relay.FlushThreshold

// udpStatusInterval bounds how long an association can outlive its account
// when it is barely transferring. A quota alone would not do it: a DNS
// forwarder moves some 60 bytes per query, so the byte boundary above can be
// hours away, and until it arrived an expired or deleted account kept its
// association.
const udpStatusInterval = time.Second

// inbound counts a datagram relayed from the client, outbound one relayed to
// it. Both answer what the account may still do, which is SessionAllowed for
// as long as the batch boundary has not been reached.
func (m *udpMeter) inbound(n int) SessionStatus {
	m.in += int64(n)
	m.inN++
	return m.record(int64(n))
}

func (m *udpMeter) outbound(n int) SessionStatus {
	m.out += int64(n)
	m.outN++
	return m.record(int64(n))
}

func (m *udpMeter) record(n int64) SessionStatus {
	m.due += n
	now := time.Now()
	if m.due < udpMeterBatch && now.Sub(m.asked) < udpStatusInterval {
		return SessionAllowed
	}
	m.flush()
	m.asked = now
	if m.acct.status == nil {
		return SessionAllowed
	}
	return m.acct.status()
}

// flush hands over what has accumulated. Both goroutines call it when they
// stop, so nothing below the batch size is lost - including the last datagram
// of an association that ends because the account said so.
func (m *udpMeter) flush() {
	if m.in > 0 && m.acct.bytesIn != nil {
		m.acct.bytesIn(m.in)
	}
	if m.out > 0 && m.acct.bytesOut != nil {
		m.acct.bytesOut(m.out)
	}
	if m.due > 0 && m.acct.counter != nil {
		m.acct.counter.Add(m.due)
	}
	if m.inN+m.outN > 0 {
		m.acct.end.addDatagrams(m.in, m.out, m.inN, m.outN)
	}
	m.in, m.out, m.due, m.inN, m.outN = 0, 0, 0, 0, 0
}

// endOfAssociation is what a UDP association does when its account may no
// longer transfer. It records the reason on the session and returns the error
// the caller reports.
//
// There is no drain here, and a TCP relay has one. The difference is in what
// the two carry: a stream has a request already in flight whose answer is
// worth waiting for, which is why handleConnect half-closes towards the
// destination and lets the reply through for the grace period. An association
// carries datagrams, each complete on its own; there is no outstanding
// exchange to finish and no half to close. So the association ends, and the
// session records why.
func (s *Server) endOfAssociation(req *Request, st SessionStatus) error {
	req.session.Exhaust(st.AccountState())
	s.config.Logger.Debug("socks: udp association ended by its account",
		"username", extractUsername(req), "status", st)
	return ErrSessionNotAllowed
}

// handleUDPTcpmux implements a custom reliable UDP-over-TCP tunnel (Command 0x83).
// This prevents STUN/WebRTC leaks bypassing the obfuscated TCP tunnel.
// The client multiplexes UDP packets into the TCP stream using a simple framing:
// [Length Uint16] [SOCKS5 UDP Header] [Payload]
func (s *Server) handleUDPTcpmux(ctx context.Context, conn conn, req *Request) error {
	// handleRequest asked the rules about the command. Where the datagrams
	// may go is a different question, asked per datagram in allowDatagram.

	// The socket carries the frames of this tunnel, so there is no tunnel
	// without one.
	tcpConn, err := socketOf(conn)
	if err != nil {
		if replyErr := sendReply(conn, serverFailure, nil); replyErr != nil {
			return fmt.Errorf("failed to send reply: %w", replyErr)
		}
		return err
	}
	nativeSession, err := s.openNative(conn, tcpConn, req)
	if err != nil {
		return err
	}
	if nativeSession != nil {
		defer nativeSession.Close()
	}

	if s.config.OnUDPTunnel != nil {
		s.config.OnUDPTunnel(tcpConn)
	}

	// The same accounting the RFC 1928 path gets. It used to have none at
	// all: a client that asked for 0x83 transferred for free, and the
	// account's quota and expiry never touched the association (F03).
	acct := s.udpAccountFor(req)

	// Unbound UDP socket to send/receive to the internet targets. It can be
	// rotated onto a new source port while nothing answers on it, to get past a
	// dead link on the path (rotatingUDP).
	egress, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind local udp socket: %w", err)
	}
	defer func() { _ = egress.Close() }()

	// Reply success (BND.ADDR/PORT is irrelevant since traffic flows via TCP)
	bindSpec := AddrSpec{IP: net.IPv4zero, Port: 0}
	if nativeSession != nil {
		bindSpec.Port = nativeSession.Port()
	}
	if err := sendReply(conn, successReply, &bindSpec); err != nil {
		return fmt.Errorf("failed to send reply: %w", err)
	}

	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	count := s.config.NativeCounters
	if count == nil {
		count = new(NativeCounters)
	}
	t := &udpTunnel{
		s:         s,
		req:       req,
		ctx:       ctx,
		tunnelCtx: tunnelCtx,
		cancel:    cancel,
		tcpConn:   tcpConn,
		// Frames are read through the handshake buffer and written to the
		// socket. The first frame of a client that does not wait for its
		// reply is already in that buffer, and reading past it from the
		// socket would drop it (plan task Ф6-5).
		tcpReader: req.bufConn,
		native:    nativeSession,
		egress:    egress,
		acct:      acct,
		count:     count,
		path:      answerPath{count: count},
		errCh:     make(chan error, 4),
	}
	// No goroutine outlives this function: it waits for all of them before
	// it returns, so nothing is still reading the handshake buffer or writing
	// into the connection once the caller starts closing it.
	var halves sync.WaitGroup
	halves.Add(2)
	// On a native association the stream has one writer of its own, and the
	// reader of the answers only queues for it (TunnelWriter).
	if nativeSession != nil {
		halves.Add(2)
		tcpMeter := t.startFallback()
		defer func() {
			if n := t.fallback.Dropped(); n > 0 {
				s.config.Logger.Debug("socks: native association dropped frames its stream could not take",
					"frames", n)
			}
		}()
		defer tcpMeter.flush()
	}
	// A tunnel is idle whenever the application has nothing to send, so no idle
	// timeout may apply to it. The session's Tunnel kind is what tells the
	// transport to stop arming the relay idle timeout; the explicit clear
	// drops the deadline the handshake already set, which the session cannot
	// retract on its own.
	req.session.Become(session.Tunnel)
	req.session.Enter(session.Relay)
	_ = tcpConn.SetDeadline(time.Time{})

	// Only one goroutine below writes to the TCP connection - the one
	// carrying datagrams from the internet, or on a native association the
	// TunnelWriter it queues for - so there is nothing to serialise. The
	// mutex that used to guard this write was taken and released once per
	// datagram to protect against a second writer that does not exist (plan
	// task Ф6-5). The reply to the request was written before either
	// goroutine started.
	//
	// A second writer would need this back. TestOnlyOneGoroutineWritesToTheTunnel
	// fails under -race if one appears.
	if t.fallback != nil {
		go func() {
			defer halves.Done()
			if err := t.fallback.Run(); err != nil {
				t.stop(err)
			}
		}()
	}

	go func() {
		defer halves.Done()
		t.answers()
	}()

	// Both ways the client sends, by this stream and natively, share one
	// dispatcher: the datagrams and lookups it may queue are the
	// association's. It closes after both readers, when the handler returns.
	meter := newUDPMeter(acct)
	t.dispatcher = newUDPDispatcher(tunnelCtx, s.datagramResolver(req.session.SLA().Dial), func(payload []byte, dest netip.AddrPort) bool {
		nw, err := egress.current().WriteToUDPAddrPort(payload, dest)
		if err != nil {
			return true
		}
		egress.sentToTarget()
		req.end.target(dest)
		if st := meter.inbound(nw); st != SessionAllowed {
			t.stop(s.endOfAssociation(req, st))
			return false
		}
		return true
	}, meter.flush)
	defer t.dispatcher.close()

	// Rotate the egress socket while it hears nothing back, so a match that
	// lands on a dead link gets a fresh draw instead of waiting out the game's
	// own retries on the same dead port. Each draw is a debug line: a target
	// that never answers, such as one-way telemetry, draws all four. The
	// first answer after a draw is one info line (replied), and the record
	// (ConnEnd) carries the draws and whether a target answered.
	halves.Add(1)
	go func() {
		defer halves.Done()
		watchDeadEgress(tunnelCtx, egress, func(n int) {
			s.config.Logger.Debug("socks: rotated udp egress socket after no replies", "rotation", n)
		})
	}()

	go func() {
		defer halves.Done()
		t.fromStream()
	}()

	if nativeSession != nil {
		go func() {
			defer halves.Done()
			t.fromNative()
		}()
	}

	// Wait for a half to fail or for the context to end. The context is
	// half of this wait, not a refinement of it: both halves return in
	// silence when the context is cancelled, so waiting on errCh alone
	// waited for a message nobody was left to send. The handler hung there
	// for good - the UDP half parked in ReadFromUDP on a socket whose close
	// is deferred to this very function, and Server.Stop waited on a handler
	// that could not return. A client using 0x83 was enough to make a
	// shutdown hang.
	select {
	case err = <-t.errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	// Whichever half is still running is told to stop, and then waited for.
	// stop is idempotent: the send to errCh is non-blocking and the socket
	// closes once.
	t.stop(err)
	halves.Wait()
	kind := AssociationTunnel
	if nativeSession != nil {
		kind = AssociationNative
	}
	s.associationEnded(req, kind, err, egress)
	return err
}

// openNative asks for the native path of a 0x84 request. A nil association
// with no error is a 0x83 request, or a node that answers 0x84 with port 0;
// an error has already been answered to the client.
func (s *Server) openNative(conn conn, tcpConn net.Conn, req *Request) (NativeAssociation, error) {
	if req.Command != UDPNativeCommand {
		return nil, nil
	}
	// A server with no native UDP at all answers as a plain SOCKS5
	// server does, and the client asks again by 0x83.
	if s.config.NativeUDP == nil {
		failure := protocolFailure("request", "command", errors.New("native UDP is not supported"))
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return nil, errors.Join(failure, connFailure("request", "reply_write", err))
		}
		return nil, failure
	}
	nativeSession, nativeErr := s.config.NativeUDP(tcpConn)
	if nativeErr != nil {
		failure := connFailure("request", "native_udp", nativeErr)
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return nil, errors.Join(failure, connFailure("request", "reply_write", err))
		}
		return nil, failure
	}
	return nativeSession, nil
}

// udpTunnel is one 0x83 or 0x84 association: the stream it is carried by,
// the socket towards the targets and, on 0x84, the native path.
type udpTunnel struct {
	s   *Server
	req *Request
	// ctx is the connection's context, which the rules are asked under;
	// tunnelCtx ends with the association.
	ctx       context.Context
	tunnelCtx context.Context
	cancel    context.CancelFunc

	tcpConn   net.Conn
	tcpReader io.Reader
	native    NativeAssociation
	fallback  *TunnelWriter
	egress    *rotatingUDP

	acct       *udpAccount
	count      *NativeCounters
	path       answerPath
	dispatcher *udpDispatcher
	errCh      chan error
}

// stop signals termination to every half. The cause goes first: the deadline
// below wakes the other half with a timeout of its own, and sent after it the
// timeout could reach errCh ahead of its cause.
func (t *udpTunnel) stop(e error) {
	select {
	case t.errCh <- e:
	default:
	}
	t.cancel()
	_ = t.tcpConn.SetDeadline(time.Now()) // unblock reads/writes
	_ = t.egress.Close()
	if t.fallback != nil {
		t.fallback.Stop()
	}
}

// startFallback builds the single writer of a native association's stream
// and returns the meter of what it carries.
func (t *udpTunnel) startFallback() *udpMeter {
	var answer [10]byte
	tcpMeter := newUDPMeter(t.acct)
	t.fallback = NewTunnelWriter(t.tcpConn, func() []byte {
		binary.BigEndian.PutUint64(answer[2:], t.native.Next())
		return answer[:]
	}, func(payload int) error {
		// The length prefix and the header belong to the tunnel, not to
		// the client's transfer.
		if st := tcpMeter.outbound(payload); st != SessionAllowed {
			return t.s.endOfAssociation(t.req, st)
		}
		return nil
	})
	t.fallback.Count(&t.count.Drops)
	return tcpMeter
}

// answers carries Internet -> client: it reads UDP responses and sends each
// natively or writes it into the TCP stream.
func (t *udpTunnel) answers() {
	s, req, egress, count, nativeSession := t.s, t.req, t.egress, t.count, t.native
	buf := make([]byte, 65535)
	meter := newUDPMeter(t.acct)
	defer meter.flush()
	for {
		select {
		case <-t.tunnelCtx.Done():
			return
		default:
		}

		c := egress.current()
		n, rAddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			// The socket may have been closed under this read by a
			// rotation, not by shutdown; if so, read from the new one.
			if egress.replaced(c) {
				continue
			}
			t.stop(fmt.Errorf("udp socket read error: %w", err))
			return
		}
		egress.replied(s.config.Logger)

		// Length prefix, header and payload are written into one pooled
		// buffer. The header used to be built into a slice of its own and
		// then copied in here, which is an allocation and a copy of the
		// whole datagram per packet (plan task Ф6-5).
		framePtr := udpBufPool.Get().(*[]byte)
		frame := AppendUDPHeaderFromAddrPort((*framePtr)[:2], rAddr)
		frame = append(frame, buf[:n]...)
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(frame)-2))

		switch {
		case nativeSession == nil:
		case len(frame)-2 > nativeSession.MaxPayload():
			count.AnswersOversize.Add(1)
		case !t.path.Native():
			count.AnswersRoute.Add(1)
		default:
			err := nativeSession.Send(frame[2:])
			if err == nil {
				count.AnswersNative.Add(1)
				udpBufPool.Put(framePtr)
				if st := meter.outbound(n); st != SessionAllowed {
					t.stop(s.endOfAssociation(req, st))
					return
				}
				continue
			}
			count.AnswersFailed.Add(1)
			// This answer goes by TCP either way; only a path that is gone
			// takes the answers after it there (see NativeAssociation.Send).
			if errors.Is(err, ErrNativePathGone) {
				t.path.Gone()
			}
		}
		if t.fallback != nil {
			// A frame the stream cannot take in time is lost, as the
			// datagram would be.
			t.fallback.Submit(frame, nil, n)
			udpBufPool.Put(framePtr)
			continue
		}
		_, err = t.tcpConn.Write(frame)
		udpBufPool.Put(framePtr)
		if err != nil {
			t.stop(fmt.Errorf("tcp write error: %w", err))
			return
		}
		// The length prefix and the header belong to the tunnel, not to
		// the client's transfer.
		if st := meter.outbound(n); st != SessionAllowed {
			t.stop(s.endOfAssociation(req, st))
			return
		}
	}
}

// fromStream carries client -> Internet by the stream: it reads
// length-prefixed datagrams and hands them to the dispatcher.
func (t *udpTunnel) fromStream() {
	s, tcpReader, nativeSession := t.s, t.tcpReader, t.native
	question := newDatagramQuestion(t.req)
	lenBuf := make([]byte, 2)
	var next [8]byte
	for {
		select {
		case <-t.tunnelCtx.Done():
			return
		default:
		}

		if _, err := io.ReadFull(tcpReader, lenBuf); err != nil {
			if t.tunnelCtx.Err() != nil {
				return
			}
			t.stop(fmt.Errorf("tcp read length error: %w", err))
			return
		}

		packetLen := binary.BigEndian.Uint16(lenBuf)
		if packetLen == 0 {
			// On 0x84 with a native path an empty frame is the client
			// saying that it does not hear the server natively, followed
			// by the counter of its next datagram at the time it decided.
			// The answers go back to this stream unless the client said
			// the opposite later by UDP, and the server answers with its
			// own counter either way. On 0x83 it is a keepalive
			// (docs/veil-spec.md, 10.6).
			if nativeSession != nil {
				if _, err := io.ReadFull(tcpReader, next[:]); err != nil {
					if t.tunnelCtx.Err() != nil {
						return
					}
					t.stop(fmt.Errorf("tcp read resync error: %w", err))
					return
				}
				counter := binary.BigEndian.Uint64(next[:])
				t.path.Lost(counter)
				nativeSession.Resync(counter)
				t.fallback.Control()
			}
			continue
		}

		framePtr := udpBufPool.Get().(*[]byte)
		frameBuf := (*framePtr)[:packetLen]
		if _, err := io.ReadFull(tcpReader, frameBuf); err != nil {
			udpBufPool.Put(framePtr)
			if t.tunnelCtx.Err() != nil {
				return
			}
			t.stop(fmt.Errorf("tcp read frame error: %w", err))
			return
		}

		hdrLen, err := parseUDPHeaderInto(frameBuf, &question.dest)
		if err != nil {
			udpBufPool.Put(framePtr)
			s.config.Logger.Warn("socks: invalid udp-tcpmux header", "error", err)
			continue
		}

		if !s.allowDatagram(t.ctx, question) {
			udpBufPool.Put(framePtr)
			s.config.Logger.Debug("socks: udp-tcpmux datagram blocked by rules",
				"destination", question.dest.String())
			continue
		}
		// A datagram by 0x83 says nothing about the answers: the client
		// sends by it what is too big for native and what it has while
		// the path is unproven, and it tells the server by the empty
		// frame when it stops hearing it.
		if nativeSession != nil {
			if int(packetLen) > nativeSession.MaxPayload() {
				t.count.ClientOversize.Add(1)
			} else {
				t.count.ClientRoute.Add(1)
			}
		}

		t.dispatcher.submit(&question.dest, frameBuf[hdrLen:])
		udpBufPool.Put(framePtr)
	}
}

// fromNative carries client -> Internet by the native path.
func (t *udpTunnel) fromNative() {
	question := newDatagramQuestion(t.req)
	handle := func(counter uint64, packet []byte) {
		hdrLen, err := parseUDPHeaderInto(packet, &question.dest)
		if err != nil || !t.s.allowDatagram(t.ctx, question) {
			return
		}
		t.count.ClientNative.Add(1)
		t.path.Heard(counter)
		t.dispatcher.submit(&question.dest, packet[hdrLen:])
	}
	heard := t.path.Heard
	for t.native.Receive(t.tunnelCtx, handle, heard) {
	}
}

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535+2)
		return &b
	},
}

// isTimeout checks if an error, or one it wraps, is a network timeout.
func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
