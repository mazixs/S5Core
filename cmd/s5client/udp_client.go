package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/internal/udpbuf"
	"github.com/mazixs/S5Core/pkg/obfs"
)

var (
	udpReadBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}
	udpFramePool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535+2)
			return &b
		},
	}
)

// SOCKS5 address types, as a reply spells them (RFC 1928, section 6).
const (
	addrIPv4 = 0x01
	addrFQDN = 0x03
	addrIPv6 = 0x04
)

// readSOCKSReply reads exactly one SOCKS5 reply from the tunnel and stops
// there, leaving whatever follows for the caller.
//
// A reply is not a packet. This used to be one Read into a 256-byte buffer,
// judged by what happened to arrive: a lone VER byte failed the "rn >= 2"
// test, so the status byte that had not arrived yet was taken for success,
// the application was told its UDP tunnel was up, and the rest of the reply
// was then read by the frame loop as 16-bit frame lengths - the first two
// bytes of it are REP and RSV, which spell a length of zero, and the next two
// are ATYP and the first octet of the bound address, which spell several
// hundred (audit finding F14).
//
// Taking the fixed part first and the address second consumes the bytes of the
// reply and nothing else, so a server that sends its reply and the first frame
// in one write is read correctly, and a server that sends half a reply and
// stops is an error rather than a success.
func readSOCKSReply(r io.Reader) ([]byte, error) {
	head := make([]byte, 4, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("reading the reply header: %w", err)
	}
	if head[0] != socks5Ver {
		return nil, fmt.Errorf("reply version %#x, want %#x", head[0], socks5Ver)
	}
	if head[2] != 0x00 {
		return nil, fmt.Errorf("reply reserved byte %#x, want 0x00", head[2])
	}

	var addrLen int
	switch head[3] {
	case addrIPv4:
		addrLen = net.IPv4len
	case addrIPv6:
		addrLen = net.IPv6len
	case addrFQDN:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, fmt.Errorf("reading the length of the bound name: %w", err)
		}
		if n[0] == 0 {
			return nil, fmt.Errorf("reply names a bound address of zero length")
		}
		head = append(head, n[0])
		addrLen = int(n[0])
	default:
		return nil, fmt.Errorf("reply address type %#x, want one of %#x, %#x, %#x", head[3], addrIPv4, addrFQDN, addrIPv6)
	}

	reply := make([]byte, len(head)+addrLen+2)
	copy(reply, head)
	if _, err := io.ReadFull(r, reply[len(head):]); err != nil {
		return nil, fmt.Errorf("reading the bound address: %w", err)
	}
	return reply, nil
}

// addrOf is the IP an address names, unmapped so that an IPv4 peer compares
// equal however the socket it arrived on spells it, or the zero Addr if the
// address names no IP at all - a connection over a pipe or a Unix socket,
// which has no datagram source that could match it.
func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// socksUDPHeader reports whether d starts with a header the server's
// socks5.ParseUDPHeader accepts. It checks the same things without building
// the address, because it runs on every datagram.
func socksUDPHeader(d []byte) bool {
	if len(d) < 4 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
		return false
	}
	switch d[3] {
	case addrIPv4:
		return len(d) >= 4+net.IPv4len+2
	case addrIPv6:
		return len(d) >= 4+net.IPv6len+2
	case addrFQDN:
		return len(d) >= 5 && d[4] != 0 && len(d) >= 5+int(d[4])+2
	}
	return false
}

// tuneUDPTunnel is shared by all associations, so that an option the kernel
// refuses is logged once rather than per association.
var tuneUDPTunnel = tcptune.Tuner(nil)

// Datagrams the application sends before the server has answered its
// association are written behind the request (docs/veil-spec.md, 10.2). A
// 0x84 request also keeps them within this bound for a second connection: a
// server that predates 0x84 refuses it and drops what followed.
const (
	earlyQueueDatagrams = 32
	earlyQueueBytes     = 64 << 10
)

// udpSetup is the part of an association that lasts until the server has
// answered it: the datagrams sent meanwhile and the tunnel of the current
// attempt, which an application that leaves closes. Its lock is taken per
// datagram during setup only.
type udpSetup struct {
	mu         sync.Mutex
	closed     bool
	retry      bool // the request may be refused and asked again by 0x83
	onSpare    bool // the attempt runs on a spare or an early upgrade and may be set up again
	conn       net.Conn
	queue      [][]byte
	bytes      int
	taken      int
	takenBytes int
	lost       int
	lostBytes  int
	writeErr   error

	// tunnelMu has its own lock, since mu is held across writes.
	tunnelMu     sync.Mutex
	current      net.Conn
	left         bool
	closedTunnel bool
}

type earlyFate int

const (
	notEarly earlyFate = iota
	earlyTaken
)

// add takes a datagram while the association is being set up. It is written
// behind the request, or held until the request is out; past the bound and
// with no request out yet, it is lost.
func (e *udpSetup) add(d []byte) earlyFate {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return notEarly
	}
	e.taken++
	e.takenBytes += len(d)
	hold := (e.conn == nil || e.retry || e.onSpare) && len(e.queue) < earlyQueueDatagrams && e.bytes+len(d) <= earlyQueueBytes
	if !hold && e.conn == nil {
		e.lost++
		e.lostBytes += len(d)
		return earlyTaken
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(d)), uint16(len(d)))
	frame = append(frame, d...)
	if hold {
		e.queue = append(e.queue, frame)
		e.bytes += len(d)
	}
	if e.conn != nil {
		e.write(frame)
	}
	return earlyTaken
}

// write sends to the tunnel of the current attempt. A tunnel that fails a
// write is closed, which ends the wait for its reply; the error is kept,
// since the reader would only see the closed connection.
func (e *udpSetup) write(b []byte) {
	if _, err := e.conn.Write(b); err != nil {
		if e.writeErr == nil {
			e.writeErr = err
		}
		_ = e.conn.Close()
		e.conn = nil
	}
}

// attach is given the tunnel of an attempt once its request is out, and the
// datagrams held so far follow the request in one write. Only a request
// that may be asked again, or one on a spare, keeps them afterwards.
func (e *udpSetup) attach(c net.Conn) {
	if !e.track(c) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = c
	if len(e.queue) > 0 {
		e.write(bytes.Join(e.queue, nil))
	}
	if !e.retry && !e.onSpare {
		e.queue, e.bytes = nil, 0
	}
}

// spare is told the attempt runs on a spare or an early upgrade: until the
// server answers, it may be set up again on a fresh transport, and the
// datagrams held go with the request once more.
func (e *udpSetup) spare() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onSpare = true
}

func (e *udpSetup) track(c net.Conn) bool {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	if e.left {
		_ = c.Close()
		e.closedTunnel = true
		return false
	}
	e.current = c
	return true
}

// accepted is told the server took the request: nothing is asked again, so
// nothing is kept for it.
func (e *udpSetup) accepted() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.retry, e.onSpare = false, false
	e.queue, e.bytes = nil, 0
}

// detach leaves the tunnel the server refused. The held datagrams wait for
// the next request; those past the bound went with the refused one only.
func (e *udpSetup) detach() {
	e.tunnelMu.Lock()
	e.current = nil
	e.tunnelMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn, e.retry, e.onSpare, e.writeErr = nil, false, false, nil
	e.lost = e.taken - len(e.queue)
	e.lostBytes = e.takenBytes - e.bytes
}

// restart leaves the tunnel of an attempt on a spare or an early upgrade that
// is set up again on a fresh transport. The held datagrams follow the request
// again; those past the bound went with the first tunnel. The request is the same and may still be
// refused and asked again.
func (e *udpSetup) restart() {
	e.tunnelMu.Lock()
	e.current = nil
	e.tunnelMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn, e.onSpare, e.writeErr = nil, false, nil
	e.lost = e.taken - len(e.queue)
	e.lostBytes = e.takenBytes - e.bytes
}

// earlyCount is what the setup did with the datagrams it took.
type earlyCount struct {
	taken, lost, sentBytes int
	writeErr               error
}

// close ends the setup. A write that failed behind an accepted request is
// returned: the tunnel it closed is not one to relay over.
func (e *udpSetup) close() earlyCount {
	e.tunnelMu.Lock()
	e.current = nil
	e.tunnelMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed, e.conn, e.queue = true, nil, nil
	return earlyCount{taken: e.taken, lost: e.lost, sentBytes: e.takenBytes - e.lostBytes, writeErr: e.writeErr}
}

// abandon is called when the application leaves. The tunnel being set up
// for it is closed, unless setup has already ended.
func (e *udpSetup) abandon() {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	e.left = true
	if e.current != nil {
		_ = e.current.Close()
		e.closedTunnel = true
	}
}

func (e *udpSetup) hasLeft() bool {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	return e.left
}

// abandoned says the setup closed the tunnel itself because the application
// left: its failure says nothing of the path. A failure before that, a dial
// that timed out among them, still counts.
func (e *udpSetup) abandoned() bool {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	return e.closedTunnel
}

// failure names the write that closed the tunnel instead of the read of a
// closed connection that followed it.
func (e *udpSetup) failure(err error) error {
	e.mu.Lock()
	werr := e.writeErr
	e.mu.Unlock()
	if werr == nil {
		return err
	}
	return &tunnelError{phase: tunnelPhaseOf(err), err: fmt.Errorf("writing a datagram behind the request: %w", werr)}
}

// tunnelDial opens the tunnel of an association and writes its request.
type tunnelDial func(attempt clientParams, request []byte) (net.Conn, clientParams, error)

// handleUDPAssociate handles the client side of UDP Associate. With
// OPTIMISTIC_CONNECT the application is told its local port at once and the
// tunnel is opened meanwhile: waiting for the server cost it two round trips
// before its first datagram (docs/plan/draft.md, Ч-3). wireReq is the
// request, 0x83 or 0x84.
func handleUDPAssociate(clientConn net.Conn, dest string, attempt clientParams, wireReq []byte) {
	associateUDP(clientConn, dest, attempt, wireReq, dialAttempt)
}

func associateUDP(clientConn net.Conn, dest string, cfg clientParams, wireReq []byte, dial tunnelDial) {
	defer func() { _ = clientConn.Close() }()
	requestedNative := len(wireReq) > 1 && wireReq[1] == socks5.UDPNativeCommand
	command := socks5.UDPTunnelCommand
	if requestedNative {
		command = socks5.UDPNativeCommand
	}
	optimistic := cfg.OptimisticConnect

	// 1. Open a local UDP socket for the application to send packets to.
	// We bind to the same IP the client connected to (usually 127.0.0.1)
	localIP, _, _ := net.SplitHostPort(clientConn.LocalAddr().String())
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		slog.Error("Failed to resolve bind address", "ip", localIP, "error", err)
		return
	}
	udpConn, err := udpbuf.ListenUDP("udp", udpAddr)
	if err != nil {
		slog.Error("Failed to bind local UDP socket", "error", err)
		_, _ = clientConn.Write([]byte{socks5Ver, socks5GenFailure, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}
	defer func() { _ = udpConn.Close() }()

	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	// VER, REP=success, RSV, then BND.ADDR and BND.PORT.
	tcpReply := socks5.AppendAddr([]byte{socks5Ver, 0x00, 0x00}, &socks5.AddrSpec{IP: boundAddr.IP, Port: boundAddr.Port})
	answer := func() bool {
		if _, err := clientConn.Write(tcpReply); err != nil {
			slog.Error("Failed to send UDP Associate reply", "error", err)
			return false
		}
		return true
	}
	// An application told success already learns of a failure by the end of
	// its connection, as RFC 1928 has it; one still waiting gets the code.
	refuse := func(reply []byte) {
		if !optimistic {
			_, _ = clientConn.Write(reply)
		}
	}

	// The reader of the application holds what it reads in setup until the
	// server has answered. obfsConn and native are set before setup is
	// closed, and the reader takes them only after that.
	setup := &udpSetup{retry: requestedNative}
	errCh := make(chan assocEnd, 4)
	var stats assocStats
	var clientUDPAddr atomic.Pointer[netip.AddrPort]
	var steady atomic.Bool
	var obfsConn net.Conn
	var native *nativeClient

	// The application may send datagrams from the address it opened the SOCKS5
	// connection from, and from nothing else: the port this client announced
	// is reachable by anything on the machine. That address is fixed for the
	// life of the association, so it is taken once here rather than rendered
	// to a string and parsed again on every datagram (review finding R11).
	// This loop is the whole UDP path of a client that runs on an ARM router
	// under GOMEMLIMIT=32MiB (docs/benchmarks/arm-router.md). A datagram used
	// to cost seven allocations: four of them were this check, and the other
	// three were the address itself - one for the *net.UDPAddr the kernel
	// path builds per read, two for the copy of it stored below. Reading and
	// writing through the netip API removes those as well, so the steady
	// state of the loop allocates nothing at all
	// (docs/benchmarks/udp-over-tcp.md).
	appIP := addrOf(clientConn.RemoteAddr())
	if !appIP.IsValid() {
		slog.Warn("UDP Associate: the application's address is not an IP, so no datagram can match it",
			"addr", clientConn.RemoteAddr())
	}

	// Go routine A: Read from application (UDP) -> write to obfsConn (TCP)
	readApp := func() {
		bufPtr := udpReadBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer udpReadBufPool.Put(bufPtr)
		for {
			n, src, err := udpConn.ReadFromUDPAddrPort(buf)
			if err != nil {
				errCh <- assocEnd{endLocal, fmt.Errorf("local udp read failed: %w", err)}
				return
			}

			// Validate it's from the same IP as the TCP connection
			stats.localIn.Add(1)
			if src.Addr().Unmap() != appIP {
				stats.sourceDrops.Add(1)
				continue // Drop packets from strangers
			}
			// A datagram without a SOCKS5 UDP header is not the application
			// speaking: the server would refuse it, and taking its port below
			// would send every answer of the association there. A reflector
			// answering a stale port did exactly that, and the answers it got
			// back carried a valid header, so the two ends looped
			// (docs/benchmarks/matrix-2026-09-22/README.md).
			if !socksUDPHeader(buf[:n]) {
				stats.headerDrops.Add(1)
				continue
			}

			// Where the answers go. Stored only when it changes, which is
			// once per association unless the application opens another
			// socket: the address is a value, and storing a value needs a
			// pointer to put it behind.
			if cur := clientUDPAddr.Load(); cur == nil || *cur != src {
				if cur != nil {
					stats.portChanges.Add(1)
				}
				stored := src
				clientUDPAddr.Store(&stored)
			}
			if !steady.Load() && setup.add(buf[:n]) == earlyTaken {
				continue
			}
			stats.addSent(n)

			// The packet from the application MUST start with a SOCKS5 UDP header
			// We just tunnel this entire frame verbatim inside length-prefixed TCP
			if native != nil {
				if native.carry(buf[:n]) == byTunnel {
					var length [2]byte
					binary.BigEndian.PutUint16(length[:], uint16(n))
					native.writer.Submit(length[:], buf[:n], n)
				}
				continue
			}
			framePtr := udpFramePool.Get().(*[]byte)
			frame := (*framePtr)[:2+n]
			binary.BigEndian.PutUint16(frame[0:2], uint16(n))
			copy(frame[2:], buf[:n])

			if _, err := obfsConn.Write(frame); err != nil {
				udpFramePool.Put(framePtr)
				errCh <- assocEnd{endTunnel, fmt.Errorf("tunnel write failed: %w", err)}
				return
			}
			udpFramePool.Put(framePtr)
			stats.streamSent.Add(1)
		}
	}

	// 2. Tell the application its port before the server answers, unless
	// it asked for the server's own code.
	if optimistic {
		if !answer() {
			return
		}
		go readApp()
	}

	// Go routine C: the application leaving ends the association, and in
	// setup closes the tunnel being opened for it.
	go func() {
		var b [1]byte
		_, err := clientConn.Read(b[:])
		setup.abandon()
		errCh <- assocEnd{endApplication, fmt.Errorf("app tcp connection closed: %w", err)}
	}()

	failed := func(err error) {
		if setup.abandoned() {
			slog.Debug("UDP Associate: the application left during setup", "error", err)
			return
		}
		err = setup.failure(err)
		logTunnelFailure(err, dest, cfg)
		refuse([]byte{socks5Ver, replyForTunnelError(err), 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}

	// 3. Open the tunnel and read the server's reply to the association.
	// The read is still covered by the handshake deadline set in
	// dialObfsTunnel: the custom command is the one place where a server
	// that does not understand it would simply never answer. A tunnel the
	// application no longer waits for fails without telling the transport
	// policy anything.
	slog.Info("UDP Associate: waiting for server reply", "command", fmt.Sprintf("%#x", command))
	cfg.requestSent = setup.attach
	cfg.setup = setup
	conn, used, err := dial(cfg, wireReq)
	cfg = used
	if err != nil {
		// dialAttempt named the phase that failed, and the hint and the
		// transport policy both depend on it.
		failed(err)
		return
	}
	obfsConn = conn
	defer func() { _ = obfsConn.Close() }()
	serverReply, err := readSOCKSReply(obfsConn)
	if err != nil {
		failed(&tunnelError{phase: phaseConnectReply, err: err})
		return
	}
	if requestedNative && mayPredateNative(serverReply[1]) {
		// A server that predates 0x84 refuses it: S5Core 2.2 by its command
		// rule, a plain SOCKS5 server as unsupported. The same answer from a
		// 2.3 server refuses UDP itself, so the association asks again by
		// 0x83 on a fresh connection, and the server is remembered only when
		// that one is accepted. The datagrams held for it follow the new
		// request.
		refusal := serverReply[1]
		setup.detach()
		_ = obfsConn.Close()
		if setup.hasLeft() {
			return
		}
		fallback := append([]byte(nil), wireReq...)
		fallback[1] = socks5.UDPTunnelCommand
		requestedNative, command = false, socks5.UDPTunnelCommand
		conn, used, err := dial(cfg, fallback)
		cfg = used
		if err != nil {
			failed(err)
			return
		}
		obfsConn = conn
		if serverReply, err = readSOCKSReply(obfsConn); err != nil {
			failed(&tunnelError{phase: phaseConnectReply, err: err})
			return
		}
		if serverReply[1] == socks5Success {
			rememberNoNative(cfg, fmt.Sprintf("0x84 refused with %#x", refusal))
		}
	}
	// The tunnel is up; the relay below must not inherit the setup deadline.
	clearDeadline(obfsConn)
	if serverReply[1] != 0x00 {
		slog.Error("Server rejected the UDP association", "command", fmt.Sprintf("%#x", command), "status", serverReply[1])
		refuse(serverReply)
		return
	}
	setup.accepted()
	if cfg.UDPTunnelTCPTuning {
		tuneUDPTunnel(obfsConn)
	}
	if requestedNative {
		if port := binary.BigEndian.Uint16(serverReply[len(serverReply)-2:]); port == 0 {
			// The server knows 0x84 and has no native path to offer.
			rememberNoNative(cfg, "no native port")
		} else if n, c, err := dialNative(obfsConn, port); err != nil {
			slog.Warn("Native UDP unavailable; association using 0x83", "error", err)
		} else {
			native = n
			defer func() { _ = c.Close() }()
		}
	}
	// From here the reader of the application sends by itself, and on a
	// native association the writer below is the only one of the tunnel.
	early := setup.close()
	if early.writeErr != nil {
		failed(&tunnelError{phase: phaseConnectReply, err: early.writeErr})
		return
	}
	stats.sent.Add(uint64(early.taken - early.lost))
	stats.sentBytes.Add(uint64(early.sentBytes))
	stats.streamSent.Add(uint64(early.taken - early.lost))
	steady.Store(true)
	if !optimistic {
		if !answer() {
			return
		}
		go readApp()
	}

	id := obfs.LogIDOf(obfsConn)
	established := []any{"conn", id, "local_udp", boundAddr.String()}
	if early.taken > 0 {
		established = append(established, "early_datagrams", early.taken, "early_dropped", early.lost)
	}
	slog.Info("UDP Tunnel established", established...)
	opened := time.Now()

	if native != nil {
		// The datagrams native does not carry wait for the stream on the
		// writer's goroutine, not on the one that reads the application:
		// one too big for native used to hold every short one behind it
		// (finding F1 of docs/reports/v2.3-rc1-audit-2026-09-26.md).
		defer native.writer.Stop()
		go func() {
			if err := native.writer.Run(); err != nil {
				errCh <- assocEnd{endTunnel, fmt.Errorf("tunnel write failed: %w", err)}
			}
		}()
		go native.run(func(d []byte) {
			if peer := clientUDPAddr.Load(); peer != nil {
				if _, err := udpConn.WriteToUDPAddrPort(d, *peer); err == nil {
					stats.addReceived(len(d))
				} else {
					stats.appWriteErrors.Add(1)
				}
			} else {
				stats.appUnknownDrops.Add(1)
			}
		})
	}

	// Go routine B: Read from obfsConn (TCP) -> write to application (UDP)
	go func() {
		lenBuf := make([]byte, 2)
		var next [8]byte
		for {
			// Read 16-bit length prefix
			if _, err := io.ReadFull(obfsConn, lenBuf); err != nil {
				errCh <- assocEnd{endTunnel, fmt.Errorf("tunnel read length failed: %w", err)}
				return
			}

			packetLen := binary.BigEndian.Uint16(lenBuf)
			if packetLen == 0 {
				// On a native association it is the server's answer to the
				// client's empty frame, with the counter of its next
				// datagram; otherwise a keepalive.
				if native != nil {
					if _, err := io.ReadFull(obfsConn, next[:]); err != nil {
						errCh <- assocEnd{endTunnel, fmt.Errorf("tunnel read resync failed: %w", err)}
						return
					}
					native.session.Resync(binary.BigEndian.Uint64(next[:]))
				}
				continue
			}

			// Read inner SOCKS5 UDP frame
			framePtr := udpFramePool.Get().(*[]byte)
			frameBuf := (*framePtr)[:packetLen]
			if _, err := io.ReadFull(obfsConn, frameBuf); err != nil {
				udpFramePool.Put(framePtr)
				errCh <- assocEnd{endTunnel, fmt.Errorf("tunnel read frame failed: %w", err)}
				return
			}

			if native != nil && !native.tcpAnswer(int(packetLen)) {
				udpFramePool.Put(framePtr)
				continue
			}
			// Must know where the client is to send UDP back
			addr := clientUDPAddr.Load()
			if addr == nil {
				stats.appUnknownDrops.Add(1)
				slog.Warn("Dropping returning UDP packet because client address unknown")
				udpFramePool.Put(framePtr)
				continue
			}

			_, err := udpConn.WriteToUDPAddrPort(frameBuf, *addr)
			udpFramePool.Put(framePtr)
			if err != nil {
				stats.appWriteErrors.Add(1)
			}
			if errors.Is(err, net.ErrClosed) {
				// The association is being torn down; answers still in the
				// tunnel have nowhere to go.
				errCh <- assocEnd{endLocal, err}
				return
			}
			if err != nil {
				slog.Warn("Failed to send UDP packet to application", "error", err)
				continue
			}
			stats.addReceived(int(packetLen))
		}
	}()

	extra := func() []any {
		attrs := []any{"conn", id}
		attrs = append(attrs, stats.diagnostics().attrs()...)
		if native != nil {
			attrs = append(attrs, native.logStats()...)
		}
		return attrs
	}
	report := startAssocReport(&stats, opened, extra, cfg.UDPDiagnosticsInterval)
	end := <-errCh
	report.stop()
	minutes.udp.Add(1)
	logAssocClosed(end, opened, stats.totals(), extra())
}
