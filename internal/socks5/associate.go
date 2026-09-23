package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
	"github.com/mazixs/S5Core/internal/session"
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

	// The account is resolved once, here, and shared by both directions:
	// where its traffic is counted, and whether it may still transfer.
	acct := s.udpAccountFor(req)

	// The socket the client talks to. Its address is what the reply carries.
	bindAddr := &net.UDPAddr{IP: s.config.BindIP, Port: 0}
	if bindAddr.IP == nil {
		bindAddr.IP = net.IPv4zero
	}
	clientConn, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind UDP port: %w", err)
	}
	defer func() { _ = clientConn.Close() }()

	// The socket the internet talks to. It takes the same local address, so
	// an operator who pinned BIND_IP to one interface still has every
	// datagram leave through it, and a port of its own, so the address the
	// client was handed is not the address targets get to see.
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindAddr.IP, Port: 0})
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind UDP egress port: %w", err)
	}
	defer func() { _ = targetConn.Close() }()

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
		return fmt.Errorf("failed to send reply: %w", err)
	}

	// We only accept packets from the client's registered IP (weak security as per RFC)
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// clientUDPAddrPtr is written by the client-facing goroutine and read by
	// the target-facing one - use atomic pointer.
	var clientUDPAddrPtr atomic.Pointer[net.UDPAddr]

	assocCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 3)
	done := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(3)
	defer func() {
		cancel()
		_ = client.SetDeadline(time.Now())
		_ = clientConn.Close()
		_ = targetConn.Close()
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
	go func() {
		defer workers.Done()
		var b [1]byte
		_, err := req.bufConn.Read(b[:])
		_ = err
		close(done)
		// Force the blocking UDP reads to unblock
		_ = clientConn.Close()
		_ = targetConn.Close()
	}()

	// Client -> target. Everything that arrives here claims to be from the
	// client, and is dropped unless it really is.
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		meter := newUDPMeter(acct)
		dispatcher := newUDPDispatcher(assocCtx, s.datagramResolver(req.session.SLA().Dial), func(payload []byte, dest *net.UDPAddr) bool {
			nw, err := targetConn.WriteToUDP(payload, dest)
			if err != nil || nw <= 0 {
				return true
			}
			if st := meter.inbound(nw); st != SessionAllowed {
				select {
				case errCh <- s.endOfAssociation(req, st):
				default:
				}
				return false
			}
			return true
		}, meter.flush)
		defer dispatcher.close()

		for {
			select {
			case <-done:
				return
			default:
			}

			// Set a short read deadline so we can check `done` periodically
			_ = clientConn.SetReadDeadline(time.Now().Add(udpPollInterval))
			n, rAddr, err := clientConn.ReadFromUDP(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				select {
				case <-done:
				default:
					errCh <- fmt.Errorf("udp read failed: %w", err)
				}
				return
			}

			if !isClientDatagram(clientUDPAddrPtr.Load(), clientIP, rAddr) {
				continue
			}

			// Parse SOCKS5 UDP header
			// IMPORTANT: copy the IP out of buf before reuse
			hdrLen, dstAddr, err := ParseUDPHeader(buf[:n])
			if err != nil {
				s.config.Logger.Warn("socks: invalid UDP header from client", "error", err)
				continue
			}

			if !s.allowDatagram(ctx, req, dstAddr) {
				s.config.Logger.Debug("socks: udp datagram blocked by rules",
					"destination", dstAddr.String())
				continue
			}

			// Remember client's actual UDP address (atomic store)
			addrCopy := &net.UDPAddr{
				IP:   make(net.IP, len(rAddr.IP)),
				Port: rAddr.Port,
				Zone: rAddr.Zone,
			}
			copy(addrCopy.IP, rAddr.IP)
			clientUDPAddrPtr.Store(addrCopy)

			dispatcher.submit(dstAddr, buf[hdrLen:n])
		}
	}()

	// Target -> client. Nothing that arrives here is ever read as a command:
	// it is a reply, and the only question is whether there is a client
	// address to send it to yet.
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		meter := newUDPMeter(acct)
		defer meter.flush()

		for {
			select {
			case <-done:
				return
			default:
			}

			_ = targetConn.SetReadDeadline(time.Now().Add(udpPollInterval))
			n, rAddr, err := targetConn.ReadFromUDP(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				select {
				case <-done:
				default:
					errCh <- fmt.Errorf("udp read failed: %w", err)
				}
				return
			}

			curClient := clientUDPAddrPtr.Load()
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

			_, werr := clientConn.WriteToUDP(pkt, curClient)
			udpBufPool.Put(pktPtr)
			if werr != nil {
				continue
			}
			// The payload is what the target sent; the header this server
			// put in front of it is not the client's traffic.
			if st := meter.outbound(n); st != SessionAllowed {
				errCh <- s.endOfAssociation(req, st)
				return
			}
		}
	}()

	// Wait for TCP close, a relay failure, or server shutdown.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	case err := <-errCh:
		return err
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
func (s *Server) allowDatagram(ctx context.Context, req *Request, dst *AddrSpec) bool {
	probe := &Request{
		Version:     Socks5Version,
		Command:     req.Command,
		AuthContext: req.AuthContext,
		RemoteAddr:  req.RemoteAddr,
		DestAddr:    dst,
		Datagram:    true,
	}
	_, allowed := s.config.Rules.Allow(ctx, probe)
	return allowed
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
}

// udpAccountFor resolves the account behind this request.
func (s *Server) udpAccountFor(req *Request) *udpAccount {
	acct := &udpAccount{
		bytesIn:  s.config.BytesAddIn,
		bytesOut: s.config.BytesAddOut,
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
func (m *udpMeter) inbound(n int) SessionStatus  { m.in += int64(n); return m.record(int64(n)) }
func (m *udpMeter) outbound(n int) SessionStatus { m.out += int64(n); return m.record(int64(n)) }

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
	m.in, m.out, m.due = 0, 0, 0
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

	// The same accounting the RFC 1928 path gets. It used to have none at
	// all: a client that asked for 0x83 transferred for free, and the
	// account's quota and expiry never touched the association (F03).
	acct := s.udpAccountFor(req)

	// Unbound UDP socket to send/receive to the internet targets
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("failed to bind local udp socket: %w", err)
	}
	defer func() { _ = udpConn.Close() }()

	// Reply success (BND.ADDR/PORT is irrelevant since traffic flows via TCP)
	bindSpec := AddrSpec{IP: net.IPv4zero, Port: 0}
	if err := sendReply(conn, successReply, &bindSpec); err != nil {
		return fmt.Errorf("failed to send reply: %w", err)
	}

	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	// Neither half outlives this function: it waits for both before it
	// returns, so nothing is still reading the handshake buffer or writing
	// into the connection once the caller starts closing it.
	var halves sync.WaitGroup
	halves.Add(2)
	// Frames are read through the handshake buffer and written to the socket.
	// The first frame of a client that does not wait for its reply is already
	// in that buffer, and reading past it from the socket would drop it (plan
	// task Ф6-5).
	tcpReader := req.bufConn
	// A tunnel is idle whenever the application has nothing to send, so no idle
	// timeout may apply to it. The session's Tunnel kind is what tells the
	// transport to stop arming the relay idle timeout; the explicit clear
	// drops the deadline the handshake already set, which the session cannot
	// retract on its own.
	req.session.Become(session.Tunnel)
	req.session.Enter(session.Relay)
	_ = tcpConn.SetDeadline(time.Time{})

	// Helper to signal termination to both goroutines.
	stopTunnel := func(e error) {
		cancel()
		_ = tcpConn.SetDeadline(time.Now()) // unblock reads/writes
		_ = udpConn.Close()
		select {
		case errCh <- e:
		default:
		}
	}

	// Only one goroutine below writes to the TCP connection - the one
	// carrying datagrams from the internet - so there is nothing to
	// serialise. The mutex that used to guard this write was taken and
	// released once per datagram to protect against a second writer that does
	// not exist (plan task Ф6-5). The reply to the request was written before
	// either goroutine started.
	//
	// A second writer would need this back. TestOnlyOneGoroutineWritesToTheTunnel
	// fails under -race if one appears.

	// Internet -> TCP: read UDP responses and write into TCP stream
	go func() {
		defer halves.Done()
		buf := make([]byte, 65535)
		meter := newUDPMeter(acct)
		defer meter.flush()
		for {
			select {
			case <-tunnelCtx.Done():
				return
			default:
			}

			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				stopTunnel(fmt.Errorf("udp socket read error: %w", err))
				return
			}

			// Length prefix, header and payload are written into one pooled
			// buffer. The header used to be built into a slice of its own and
			// then copied in here, which is an allocation and a copy of the
			// whole datagram per packet (plan task Ф6-5).
			framePtr := udpBufPool.Get().(*[]byte)
			frame := AppendUDPHeaderFromAddr((*framePtr)[:2], rAddr)
			frame = append(frame, buf[:n]...)
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(frame)-2))

			_, err = tcpConn.Write(frame)
			udpBufPool.Put(framePtr)
			if err != nil {
				stopTunnel(fmt.Errorf("tcp write error: %w", err))
				return
			}
			// The length prefix and the header belong to the tunnel, not to
			// the client's transfer.
			if st := meter.outbound(n); st != SessionAllowed {
				stopTunnel(s.endOfAssociation(req, st))
				return
			}
		}
	}()

	// TCP -> Internet: read length-prefixed UDP packets and send out
	go func() {
		defer halves.Done()
		meter := newUDPMeter(acct)
		dispatcher := newUDPDispatcher(tunnelCtx, s.datagramResolver(req.session.SLA().Dial), func(payload []byte, dest *net.UDPAddr) bool {
			nw, err := udpConn.WriteToUDP(payload, dest)
			if err != nil {
				return true
			}
			if st := meter.inbound(nw); st != SessionAllowed {
				stopTunnel(s.endOfAssociation(req, st))
				return false
			}
			return true
		}, meter.flush)
		defer dispatcher.close()
		lenBuf := make([]byte, 2)
		for {
			select {
			case <-tunnelCtx.Done():
				return
			default:
			}

			if _, err := io.ReadFull(tcpReader, lenBuf); err != nil {
				if tunnelCtx.Err() != nil {
					return
				}
				stopTunnel(fmt.Errorf("tcp read length error: %w", err))
				return
			}

			packetLen := binary.BigEndian.Uint16(lenBuf)
			if packetLen == 0 {
				continue // Keep-alive
			}

			framePtr := udpBufPool.Get().(*[]byte)
			frameBuf := (*framePtr)[:packetLen]
			if _, err := io.ReadFull(tcpReader, frameBuf); err != nil {
				udpBufPool.Put(framePtr)
				if tunnelCtx.Err() != nil {
					return
				}
				stopTunnel(fmt.Errorf("tcp read frame error: %w", err))
				return
			}

			hdrLen, dstAddr, err := ParseUDPHeader(frameBuf)
			if err != nil {
				udpBufPool.Put(framePtr)
				s.config.Logger.Warn("socks: invalid udp-tcpmux header", "error", err)
				continue
			}

			if !s.allowDatagram(ctx, req, dstAddr) {
				udpBufPool.Put(framePtr)
				s.config.Logger.Debug("socks: udp-tcpmux datagram blocked by rules",
					"destination", dstAddr.String())
				continue
			}

			dispatcher.submit(dstAddr, frameBuf[hdrLen:])
			udpBufPool.Put(framePtr)
		}
	}()

	// Wait for a half to fail or for the context to end. The context is
	// half of this wait, not a refinement of it: both halves return in
	// silence when the context is cancelled, so waiting on errCh alone
	// waited for a message nobody was left to send. The handler hung there
	// for good - the UDP half parked in ReadFromUDP on a socket whose close
	// is deferred to this very function, and Server.Stop waited on a handler
	// that could not return. A client using 0x83 was enough to make a
	// shutdown hang.
	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	// Whichever half is still running is told to stop, and then waited for.
	// stopTunnel is idempotent: the send to errCh is non-blocking and the
	// socket closes once.
	stopTunnel(err)
	halves.Wait()
	return err
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
