package main

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mazixs/S5Core/internal/diagnostics"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/udpbuf"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// Liveness of the native path (docs/veil-spec.md, 10.6). Only an answer to a
// probe shows that both directions work: the server's data shows one of them,
// and a client whose datagrams stopped reaching the server went on hearing it.
const (
	// The client hears the server while a verified packet came this recently,
	// or while its probes are not yet overdue (nativeClient.hears).
	nativeFresh = time.Second
	// A probe is overdue this long after it went out, or after twice the
	// smoothed RTT of the probes if that is longer.
	nativeAnswerWait = 250 * time.Millisecond
	// An association is active this long after a datagram either way.
	nativeActiveFor = 2 * time.Second
	// The probe of an active association, or of one whose probe went
	// unanswered: 400-600 ms, so that its answer keeps the path fresh.
	nativeActiveEvery  = 400 * time.Millisecond
	nativeActiveJitter = 200 * time.Millisecond
	// The NAT keepalive of an idle association: 10-20 s.
	nativeIdleEvery  = 10 * time.Second
	nativeIdleJitter = 10 * time.Second
	// A path is down after this many probes in a row without an answer, the
	// first of them at least nativeMissSpan ago: one lost probe is ordinary
	// on a path with a percent of loss, and the game would leave native
	// exactly where it needs it.
	nativeMisses   = 3
	nativeMissSpan = time.Second
	// A path that is down, or not yet verified, is probed after 1 s, and the
	// wait doubles up to 10 s.
	nativeRetryFirst = time.Second
	nativeRetryMax   = 10 * time.Second
	// A probe answered alone is recorded, and may shorten srtt, only this long
	// after the last probe the count lost track of, at a loss or at an answer
	// while several were out: until then a late answer to that one could pass
	// for the answer to this one.
	nativeStrayFor = 10 * time.Second
)

// The limit of the path (docs/veil-spec.md, 10.7).
const (
	// A round of size probes ends this long after the control's answer, or
	// as long again as the control took if that is longer.
	nativeSearchSlack        = 25 * time.Millisecond
	nativeRecoveryEvery      = 30 * time.Second
	nativeRecoverySearches   = 3
	nativeLimitAnnouncements = 3
	// A datagram longer than native carries is dropped, and this many dropped
	// one way move the long ones of the association to 0x83: the size search
	// of quic-go loses a few, an application that keeps sending them would
	// lose them all.
	nativeOversizeDrops = 8
)

// The search for a faster route (docs/veil-spec.md, 10.6.1). A provider can
// spread the flows to one server over routes by the hash of their addresses
// and ports, and the source port of the native socket is the client's to
// choose.
const (
	// The search starts once the association is this old, and only while it
	// is active: most associations end before it.
	nativeRouteAfter = 3 * time.Second
	// A candidate goes this long after the one before, and a second after
	// the last challenge: the server reflects one a second.
	nativeRouteEvery     = 1200 * time.Millisecond
	nativeChallengeEvery = time.Second
	// A candidate wins when its round trip is shorter than the shortest of
	// the last nativeRouteSamples of the route by nativeRouteGain, or by
	// nativeRouteShare percent of it if that is more.
	nativeRouteGain    = 10 * time.Millisecond
	nativeRouteShare   = 15
	nativeRouteSamples = 8
	// The replaced socket is read this long after the server answered on the
	// new one, for its datagrams still on the way.
	nativeRouteDrain = time.Second
	// maxRouteCandidates bounds UDP_NATIVE_ROUTE_CANDIDATES.
	maxRouteCandidates = 8
)

// What the server answers probes with, known from its first answer.
const (
	serverUnknown int32 = iota
	serverSizes
	serverLegacy // 2.3.0-rc1: empty answers, no search
)

// carried is what carry did with a datagram.
type carried int

const (
	byTunnel carried = iota // the caller sends it by 0x83
	byNative
	dropped
)

// noNativeFor is how long a server without native UDP is asked for 0x83
// directly: it may be upgraded, and nothing else would tell.
const noNativeFor = 10 * time.Minute

// noNative remembers servers without native UDP, by nativeKey. A server that
// predates 0x84 refuses it, and every association would pay for a second
// connection.
var noNative sync.Map // string -> time.Time

// nativeKey names the node an answer came from: the transport and the
// address it dials. WS_URL and SERVER_ADDR may reach different nodes.
func nativeKey(cfg clientParams) string {
	if cfg.usesWS() {
		return "ws " + cfg.WSUrl
	}
	return "obfs " + cfg.ServerAddr
}

func rememberNoNative(cfg clientParams, reason string) {
	if prev, ok := noNative.Swap(nativeKey(cfg), time.Now()); !ok || time.Since(prev.(time.Time)) >= noNativeFor {
		slog.Info("Server has no native UDP; associations use 0x83", "reason", reason,
			"transport", cfg.effectiveTransport(), "for", noNativeFor.String())
	}
}

// udpCommandFor is the command an association asks the server for.
// mayPredateNative reports a refusal of 0x84 that a server without it gives:
// S5Core 2.2 and earlier refuse unknown commands by their rules, a plain
// SOCKS5 server says the command is not supported.
func mayPredateNative(status byte) bool {
	return status == socks5CmdNotSup || status == replyNotAllowed
}

func udpCommandFor(cfg clientParams) byte {
	if !cfg.UDPNative {
		return socks5.UDPTunnelCommand
	}
	if at, ok := noNative.Load(nativeKey(cfg)); ok && time.Since(at.(time.Time)) < noNativeFor {
		return socks5.UDPTunnelCommand
	}
	return socks5.UDPNativeCommand
}

// dialNative opens the native path to the port the server announced, on the
// address the tunnel reached, with the keys of the tunnel. The client owns
// every socket of the path from then on, and close closes them.
func dialNative(tunnel net.Conn, port uint16, candidates int) (*nativeClient, error) {
	keys, err := obfs.DatagramKeysOf(tunnel)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(tunnel.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	c, err := dialRoute(remote)
	if err != nil {
		return nil, err
	}
	n := newNativeClient(c, nativeudp.NewSession(keys), nil)
	n.dial = func() (datagramConn, error) {
		c, err := dialRoute(remote)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	n.candidates = candidates
	n.logID = obfs.LogIDOf(tunnel)
	n.flow = diagnostics.FlowOf(tunnel)
	n.writer = socks5.NewTunnelWriter(tunnel, n.signalFrame, nil)
	n.signal = n.writer.Control
	return n, nil
}

// dialRoute opens a socket to the server's native port. A candidate's is
// opened as the first one: the source port is the kernel's pick.
func dialRoute(remote *net.UDPAddr) (*net.UDPConn, error) {
	c, err := udpbuf.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	if err := nativeudp.DontFragment(c); err != nil {
		slog.Debug("Native UDP socket may fragment datagrams longer than the path", "error", err)
	}
	return c, nil
}

// datagramConn is the client's connected UDP socket to the server's native
// port.
type datagramConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

// nativeSocket is one socket of the path: the current one, a candidate, or
// the one a move replaced. retired is set before the client closes it: the
// end of any other socket is the end of the association.
type nativeSocket struct {
	datagramConn
	retired atomic.Bool
}

// challenge is a route challenge that came on a socket other than the
// current one, at the client's clock.
type challenge struct {
	s     *nativeSocket
	at    int64
	token [16]byte
}

// nativeClient starts on 0x83 and moves datagrams to native once a probe is
// answered, so a blocked UDP port never stalls the association.
//
// The server answers natively only while the client says it hears it: a
// native datagram or a probe with nativeudp.ProbeHeard says so, the empty
// frame that signal writes to the tunnel says the opposite, and a datagram
// by 0x83 says nothing. The frame and the server's answer to it carry the
// counters of both sides, so that datagrams lost past the window do not end
// the path.
type nativeClient struct {
	// conn is the current socket: every probe and native datagram goes by it.
	conn atomic.Pointer[nativeSocket]
	// dial opens a socket for a candidate route, at most candidates of them
	// per association (UDP_NATIVE_ROUTE_CANDIDATES).
	dial       func() (datagramConn, error)
	candidates int
	// moving is set from the win of a candidate until the server answers on
	// it: the application's datagrams go by 0x83 meanwhile, since the server
	// takes native ones only from the address it answers. carrying orders it
	// against the native sends of carry.
	moving   atomic.Bool
	carrying sync.RWMutex
	// proves is set once the server challenged the route, challengeAt is
	// when the last challenge came on the current socket. challenges hands
	// watch the ones that come on another.
	proves      atomic.Bool
	challengeAt atomic.Int64
	challenges  chan challenge
	deliver     func([]byte)
	// sockets are the open sockets, ended is set by close; readers are their
	// readers, and done ends watch.
	mu      sync.Mutex
	sockets []*nativeSocket
	ended   bool
	readers sync.WaitGroup
	done    chan struct{}
	// epoch keeps the Go monotonic clock. Liveness counters store durations
	// from it, never wall timestamps that can jump during NTP adjustment.
	epoch   time.Time
	logID   string
	flow    diagnostics.Flow // the tunnel's, for the path's changes and the probes' round trips
	session *nativeudp.Session
	// signal asks for the empty frame to be written, and must not wait for
	// the tunnel: a stream whose send buffer is full would hold the probes,
	// and with them the way back to native.
	signal func()
	jitter func() float64
	// writer is the one writer of the tunnel: the empty frame and the
	// datagrams native does not carry (docs/veil-spec.md, 10.6).
	writer *socks5.TunnelWriter
	frame  [10]byte // the writer's

	up       atomic.Bool
	usedData atomic.Bool
	// told is set once the server is told to answer by TCP, which is where
	// it starts, and cleared once it is told that the client hears it.
	told atomic.Bool
	// tellNext is the counter of the next datagram when the client last
	// decided to tell: the server places the frame by it, against the
	// datagrams and heard probes sealed after (answerPath on the server).
	tellNext atomic.Uint64
	lastSeen atomic.Int64 // a verified packet from the server
	lastUsed atomic.Int64 // an application datagram or the server's data
	// deafAt is when the second of the probes unanswered in a row is
	// overdue, and math.MaxInt64 while fewer than two are.
	deafAt atomic.Int64
	acked  chan struct{}
	// sized gets the answers to size probes, by size.
	sized             chan nativeudp.Answer
	limitACK          chan nativeudp.Answer
	recoverySupported atomic.Bool
	poked             chan struct{}
	// echoAt is when the last route challenge was echoed, 0 once the echo's
	// answer came; echoRTT is the round trip of that answer, 0 once watch
	// took it.
	echoAt  atomic.Int64
	echoRTT atomic.Int64
	// server is how the server answers probes (serverUnknown until it does).
	server atomic.Int32
	// bounded is set while datagrams longer than native carries are dropped
	// rather than sent by 0x83.
	bounded atomic.Bool
	draw    func(n int) int
	stats   nativeStats
}

// nativeStats is where the datagrams of the association went, for the line
// that logs its end: delivery alone does not say which path carried them.
type nativeStats struct {
	sent, sentOversize, sentTCP                  atomic.Uint64
	received, receivedTCP                        atomic.Uint64
	droppedSent, droppedRecv                     atomic.Uint64
	sizeProbes                                   atomic.Uint64
	dataWriteErrors, readErrors, rejectedPackets atomic.Uint64
	probesSent, probeWriteErrors                 atomic.Uint64
	sizeProbesSent, sizeProbeTooBig              atomic.Uint64
	routeCandidates                              atomic.Uint64
	routeMoved                                   atomic.Bool
}

// logStats is the native half of the association's line. The closing line is
// final: what the server sent and has not come by then is lost.
func (n *nativeClient) logStats(final bool) []any {
	var dropped uint64
	if n.writer != nil {
		dropped = n.writer.Dropped()
	}
	loss := n.session.Loss()
	if final {
		loss = n.session.FinalLoss()
	}
	return []any{"native_sent", n.stats.sent.Load(), "tcp_sent_oversize", n.stats.sentOversize.Load(),
		"native_probes_sent", n.stats.probesSent.Load(), "native_probe_write_errors", n.stats.probeWriteErrors.Load(),
		"size_probes_sent", n.stats.sizeProbesSent.Load(), "size_probe_too_big", n.stats.sizeProbeTooBig.Load(),
		"native_up", n.up.Load(), "native_heard", n.hears(n.clock(time.Now())),
		"native_data_write_errors", n.stats.dataWriteErrors.Load(), "native_read_errors", n.stats.readErrors.Load(),
		"native_rejected_packets", n.stats.rejectedPackets.Load(),
		"tcp_sent_other", n.stats.sentTCP.Load(), "native_received", n.stats.received.Load(),
		"tcp_received", n.stats.receivedTCP.Load(), "tunnel_drops", dropped,
		"native_limit", n.session.Limit(), "size_probes", n.stats.sizeProbes.Load(),
		"dropped_oversize_sent", n.stats.droppedSent.Load(), "dropped_oversize_received", n.stats.droppedRecv.Load(),
		"native_lost", loss.Lost, "native_late", loss.Late,
		"native_route_candidates", n.stats.routeCandidates.Load(), "native_route_moved", n.stats.routeMoved.Load()}
}

var heardProbe = []byte{nativeudp.ProbeHeard}

func newNativeClient(conn datagramConn, session *nativeudp.Session, signal func()) *nativeClient {
	n := &nativeClient{epoch: time.Now(), session: session, signal: signal, jitter: rand.Float64, draw: rand.IntN,
		acked: make(chan struct{}, 1), sized: make(chan nativeudp.Answer, 16), limitACK: make(chan nativeudp.Answer, 16), poked: make(chan struct{}, 1),
		challenges: make(chan challenge, 1), done: make(chan struct{})}
	first := &nativeSocket{datagramConn: conn}
	n.conn.Store(first)
	n.sockets = []*nativeSocket{first}
	n.told.Store(true)
	n.bounded.Store(true)
	n.deafAt.Store(math.MaxInt64)
	n.lastUsed.Store(-int64(nativeActiveFor))
	n.lastSeen.Store(-int64(nativeFresh))
	return n
}

func (n *nativeClient) send(kind byte, payload []byte) error {
	return n.session.SealWriteWithLimitError(kind, payload, n.write)
}

func (n *nativeClient) write(wire []byte) error { return writeOn(n.current(), wire) }

func writeOn(c datagramConn, wire []byte) error {
	_, err := c.Write(wire)
	if errors.Is(err, syscall.EMSGSIZE) {
		// The PTB for an earlier datagram, reported by the next call on the
		// connected socket: this one was not sent. Under IP_PMTUDISC_PROBE
		// the socket does not size datagrams by it, so a second EMSGSIZE is
		// about this datagram (docs/veil-spec.md, 10.7).
		_, err = c.Write(wire)
	}
	return err
}

func (n *nativeClient) current() *nativeSocket { return n.conn.Load() }

// listen adds s to the sockets of the path, unless it is one, and starts its
// reader. Once the association has ended it closes s instead.
func (n *nativeClient) listen(s *nativeSocket) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ended {
		_ = s.Close()
		return false
	}
	if !slices.Contains(n.sockets, s) {
		n.sockets = append(n.sockets, s)
	}
	n.readers.Add(1)
	go n.read(s)
	return true
}

// retire closes a socket the path no longer uses.
func (n *nativeClient) retire(s *nativeSocket) {
	s.retired.Store(true)
	_ = s.Close()
	n.mu.Lock()
	n.sockets = slices.DeleteFunc(n.sockets, func(o *nativeSocket) bool { return o == s })
	n.mu.Unlock()
}

// close ends the association: every socket of the path and the watcher.
func (n *nativeClient) close() {
	n.mu.Lock()
	if n.ended {
		n.mu.Unlock()
		return
	}
	n.ended = true
	sockets := n.sockets
	n.sockets = nil
	n.mu.Unlock()
	close(n.done)
	for _, s := range sockets {
		_ = s.Close()
	}
}

// sendProbe sends a probe the server reads: the form of 2.3.0-rc1 to a server
// that answered like one, the extended form to any other.
func (n *nativeClient) sendProbe(p nativeudp.ExtendedProbe) error {
	var err error
	if n.server.Load() != serverLegacy {
		// Search controls can be as short as 48 bytes and start only after a
		// normal ACK. Keep their geometry; ordinary probes establish routes.
		p.RouteProof = p.Size == 0
		err = n.session.SealWriteExtendedProbe(p, n.write)
	} else {
		var payload []byte
		if p.Heard {
			payload = heardProbe
		}
		err = n.send(nativeudp.KindProbe, payload)
	}
	if p.Size != 0 && errors.Is(err, syscall.EMSGSIZE) {
		// Reaching the interface MTU is an expected size-search outcome.
		// It says nothing about whether ordinary control probes can leave.
		n.stats.sizeProbeTooBig.Add(1)
	} else if err != nil {
		n.stats.probeWriteErrors.Add(1)
	} else if p.Size != 0 {
		n.stats.sizeProbesSent.Add(1)
	} else {
		// Only local socket acceptance, never proof of the peer's receipt.
		n.stats.probesSent.Add(1)
	}
	return err
}

// tell asks the server to answer by TCP, with the counter the client is at
// now: a native datagram or heard probe sealed after this outranks the frame
// however late the frame comes. A signal still waiting to be written covers
// this one and carries the later counter. Once told, the server is told
// again only when again is set.
func (n *nativeClient) tell(again bool) {
	if n.told.Swap(true) && !again {
		return
	}
	next := n.session.Next()
	for cur := n.tellNext.Load(); next > cur; cur = n.tellNext.Load() {
		if n.tellNext.CompareAndSwap(cur, next) {
			break
		}
	}
	n.signal()
}

// signalFrame is the empty frame of the last decision to tell. It runs on the
// writer's goroutine.
func (n *nativeClient) signalFrame() []byte {
	binary.BigEndian.PutUint64(n.frame[2:], n.tellNext.Load())
	return n.frame[:]
}

// hears reports whether the client hears the server natively: the path is up,
// and a verified packet came less than nativeFresh ago or no two probes in a
// row are overdue. Datagrams, the signal and ProbeHeard all follow it, so one
// lost answer, a longer RTT or a first datagram after a pause keep the
// association native (finding F3 of docs/reports/v2.3-rc1-audit-2026-09-26.md).
func (n *nativeClient) clock(now time.Time) int64 { return int64(now.Sub(n.epoch)) + 1 }

func (n *nativeClient) hears(now int64) bool {
	return n.up.Load() && (now-n.lastSeen.Load() < int64(nativeFresh) || now < n.deafAt.Load())
}

// deafFrom is when hears turns false with no packet from the server, once two
// probes in a row are unanswered.
func (n *nativeClient) deafFrom() (int64, bool) {
	at := n.deafAt.Load()
	if at == math.MaxInt64 {
		return 0, false
	}
	return max(at, n.lastSeen.Load()+int64(nativeFresh)), true
}

func (n *nativeClient) poke() {
	select {
	case n.poked <- struct{}{}:
	default:
	}
}

// used records a datagram either way. The first one after a pause wakes the
// watcher, whose next probe is otherwise the idle keepalive: a path that
// breaks under the traffic that follows would go unnoticed for up to 20 s.
func (n *nativeClient) used(now int64) {
	if now-n.lastUsed.Swap(now) >= int64(nativeActiveFor) {
		n.poke()
	}
}

// drop reports whether a datagram longer than native carries is dropped: it
// is while the association is bounded and the native path is verified and
// heard. An unavailable path must not make a working TCP fallback lose data.
// The nativeOversizeDrops-th dropped one way ends that (docs/veil-spec.md, 10.7).
func (n *nativeClient) drop(count *atomic.Uint64) bool {
	if !n.bounded.Load() || !n.hears(n.clock(time.Now())) {
		return false
	}
	if count.Add(1) >= nativeOversizeDrops && n.bounded.Swap(false) {
		slog.Info("Native UDP: the application keeps sending datagrams longer than native carries; they use 0x83",
			"conn", n.logID, "max_payload", n.session.MaxPayload())
	}
	return true
}

// carry sends d natively when it can. A datagram it leaves byTunnel is the
// caller's to send by 0x83.
func (n *nativeClient) carry(d []byte) carried {
	now := n.clock(time.Now())
	n.used(now)
	if len(d) > n.session.MaxPayload() {
		if n.drop(&n.stats.droppedSent) {
			return dropped
		}
		n.stats.sentOversize.Add(1)
		return byTunnel
	}
	if !n.up.Load() {
		n.stats.sentTCP.Add(1)
		return byTunnel
	}
	// A move to a faster route sets moving under the write lock, so that no
	// datagram checked here before it goes out after.
	n.carrying.RLock()
	defer n.carrying.RUnlock()
	if n.moving.Load() {
		n.stats.sentTCP.Add(1)
		return byTunnel
	}
	// Up but not heard lately: the association just woke from idle, or the
	// path is failing. The answers go by TCP until the probe answers which,
	// and nothing is logged.
	if !n.hears(now) {
		n.tell(false)
		n.poke()
		n.stats.sentTCP.Add(1)
		return byTunnel
	}
	if err := n.send(nativeudp.KindData, d); err != nil {
		if errors.Is(err, nativeudp.ErrPayloadTooLarge) {
			n.stats.sentOversize.Add(1)
			return byTunnel
		}
		n.stats.dataWriteErrors.Add(1)
		n.poke()
		n.stats.sentTCP.Add(1)
		return byTunnel
	}
	n.stats.sent.Add(1)
	n.told.Store(false)
	if !n.usedData.Swap(true) {
		slog.Info("Native UDP carrying application datagrams", "conn", n.logID)
	}
	return byNative
}

// tcpAnswer records a datagram of the server that came by TCP. One native
// could carry, while the client has not told the server to use TCP, is the
// server not knowing that the client hears it: its heard probe was lost, or
// arrived before a loss signal it outranks. The association counts as active
// then, so the next probe says ProbeHeard within one active interval rather
// than at the idle keepalive. It reports whether to deliver the datagram: a
// long one is dropped as carry drops it.
func (n *nativeClient) tcpAnswer(size int) bool {
	if size > n.session.MaxPayload() {
		if n.drop(&n.stats.droppedRecv) {
			return false
		}
	} else if n.up.Load() && !n.told.Load() {
		n.used(n.clock(time.Now()))
	}
	n.stats.receivedTCP.Add(1)
	return true
}

// run probes the path and reads its sockets until close, or until a socket
// the client did not retire is closed. deliver gets the server's datagrams,
// from every socket that is read.
func (n *nativeClient) run(deliver func([]byte)) {
	n.deliver = deliver
	if n.listen(n.current()) {
		n.watch()
	}
	n.readers.Wait()
}

// read reads s until it is closed. An answer speaks for the path only on the
// current socket. On another a challenge goes to watch, which knows whether
// it answers a candidate, and any other answer is to a probe of the route
// the path left.
func (n *nativeClient) read(s *nativeSocket) {
	defer n.readers.Done()
	var b [nativeudp.MaxWire + 1]byte
	failed := false
	for {
		r, err := s.Read(b[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				if !s.retired.Load() {
					n.close()
				}
				return
			}
			n.stats.readErrors.Add(1)
			// An ICMP error is an answer about one datagram, not the end of
			// the socket: the probes decide whether the path works. The
			// pause keeps an error that repeats from spinning the loop.
			if failed {
				time.Sleep(10 * time.Millisecond)
			}
			failed = true
			continue
		}
		failed = false
		p, err := n.session.Open(b[:r])
		if err != nil {
			n.stats.rejectedPackets.Add(1)
			continue
		}
		now := n.clock(time.Now())
		current := n.current() == s
		switch p.Kind {
		case nativeudp.KindProbeAck:
			answer, sizes := nativeudp.ParseAnswer(p.Data)
			if answer.RouteChallenge {
				if !current {
					select {
					case n.challenges <- challenge{s: s, at: now, token: answer.RouteToken}:
					default:
					}
					continue
				}
				// A challenge is not confirmation of the application route.
				// Echo once immediately; ordinary probing cadence is unchanged.
				n.proves.Store(true)
				n.challengeAt.Store(now)
				n.echoAt.Store(now)
				_ = n.sendProbe(nativeudp.ExtendedProbe{RouteEcho: true, RouteToken: answer.RouteToken})
				continue
			}
			if !current {
				continue
			}
			// The server answers on the socket the path moves to: it moved.
			// Checked after moving, which is set after the socket changed.
			if n.moving.Load() && n.current() == s {
				n.moving.Store(false)
			}
			n.lastSeen.Store(now)
			size := answer.Size
			if answer.Generation != 0 {
				n.recoverySupported.Store(true)
			}
			if sizes {
				n.server.CompareAndSwap(serverUnknown, serverSizes)
			} else {
				n.server.CompareAndSwap(serverUnknown, serverLegacy)
			}
			if size != 0 {
				// An answer to a size probe is as long as the probe was.
				if size == r {
					select {
					case n.sized <- answer:
					default:
					}
				}
				break
			}
			if answer.Limit != 0 {
				select {
				case n.limitACK <- answer:
				default:
				}
			}
			if at := n.echoAt.Load(); at != 0 && answer.Generation == 0 {
				// The echo goes with generation 0, every other probe with a
				// later one, and the answer has the generation of its probe
				// (docs/veil-spec.md, 10.6): this answer is the echo's.
				n.echoRTT.Store(now - at)
				n.echoAt.Store(0)
			}
			select {
			case n.acked <- struct{}{}:
			default:
			}
		case nativeudp.KindData:
			n.lastSeen.Store(now)
			n.used(now)
			if len(p.Data) > n.session.MaxPayload() && n.drop(&n.stats.droppedRecv) {
				break
			}
			n.stats.received.Add(1)
			n.deliver(p.Data)
		}
	}
}

// watch owns the probes: when they go out, and what their answers mean. It
// also owns the search for a faster route and the move to one.
func (n *nativeClient) watch() {
	var (
		unanswered int
		firstSent  time.Time
		lastProbe  time.Time
		draw       float64 // drawn per probe, so recomputing the wait does not redraw it
		retry      = nativeRetryFirst
		verified   bool
		reported   bool          // a path never heard was logged
		srtt       time.Duration // see acked, 0 before the first round trip
		strayUntil time.Time     // see nativeStrayFor
		// The search for the limit of the path (docs/veil-spec.md, 10.7).
		search             *nativeudp.Search
		roundAt            time.Time // when the round in flight went out, zero when none is
		roundEnd           time.Time
		roundWait          bool   // a round waits for the next answer
		announce           int    // the limit found, 0 until then
		generation         uint32 = 1
		announceGeneration uint32 = 1
		recovering         bool
		recoveries         int
		recoveryAt         time.Time
		pendingLimit       int
		announcements      int
		probeErrorBaseline uint64
		// The search for a faster route (docs/veil-spec.md, 10.6.1).
		started       = time.Now()
		recent        [nativeRouteSamples]time.Duration // the round trips srtt takes, the last ones
		samples       int
		lastCandidate time.Time
		candidate     *nativeSocket // the one whose challenge is awaited
		candidateAt   int64         // when its probe went, by n.clock
		need          time.Duration // the round trip it must not exceed to win
		before, after time.Duration // the round trips of the routes a move left and took
		token         [16]byte
		echoDue       time.Time     // when the winner echoes, zero when none waits to
		retired       *nativeSocket // the socket a move replaced, still read
		drainAt       time.Time     // when retired is closed, zero until the move is answered
		awaiting      bool          // the move waits for the server's answer on the new socket
		rerouted      bool          // the search of the limit follows a move, and may lower it
	)
	active := func(now time.Time) bool { return n.clock(now)-n.lastUsed.Load() < int64(nativeActiveFor) }
	probe := func(now time.Time) {
		heard := n.hears(n.clock(now))
		switch {
		case !n.up.Load() && (verified || missedProbeWindow(unanswered, firstSent, now)):
			// Synchronize even before the first native answer. Long initial
			// blocking spends counters just like a previously working path.
			n.tell(true)
		case !heard && active(now):
			// An active association that stopped hearing the server: the
			// answers go by TCP now, not once the path is found lost.
			n.tell(false)
		}
		if heard {
			n.told.Store(false)
		}
		if pendingLimit != 0 {
			if announcements >= nativeLimitAnnouncements {
				// The server may have received the proposal even though every
				// acknowledgement was lost. Cancel with a newer generation of
				// the still-committed limit; keep announcing that generation on
				// ordinary probes so losing the first cancellation is harmless.
				// No extra probes or size searches are added by the rollback.
				generation++
				announceGeneration = generation
				announce = n.session.Limit()
				n.session.ApplyProbeLimit(nativeudp.ExtendedProbe{Generation: generation, Limit: announce})
				pendingLimit = 0
				recoveryAt = now.Add(nativeRecoveryEvery)
				slog.Info("Native UDP limit proposal unconfirmed; retaining committed limit", "conn", n.logID,
					"limit", announce, "generation", generation)
			} else {
				announcements++
			}
		}
		if unanswered == 0 {
			firstSent = now
			probeErrorBaseline = n.stats.probeWriteErrors.Load()
		}
		_ = n.sendProbe(nativeudp.ExtendedProbe{Heard: heard, Limit: announce, Generation: announceGeneration})
		unanswered++
		if unanswered == 2 {
			n.deafAt.Store(n.clock(now.Add(max(nativeAnswerWait, 2*srtt))))
		}
		lastProbe = now
		draw = n.jitter()
	}
	nextProbe := func(now time.Time) time.Time {
		var every time.Duration
		switch {
		case !n.up.Load():
			every = retry
		case unanswered > 0 || active(now):
			every = nativeActiveEvery + time.Duration(draw*float64(nativeActiveJitter))
		default:
			every = nativeIdleEvery + time.Duration(draw*float64(nativeIdleJitter))
		}
		return lastProbe.Add(every)
	}
	// deafening is when an active association that has not told the server
	// stops hearing it before the next probe: the watcher wakes then to tell,
	// since an application that only listens sends nothing that would.
	deafening := func(now time.Time) (time.Time, bool) {
		at, ok := n.deafFrom()
		if !ok || !n.up.Load() || n.told.Load() || !active(now) {
			return time.Time{}, false
		}
		return n.epoch.Add(time.Duration(at - 1)), true
	}
	sendRound := func(now time.Time) {
		for _, size := range search.Round() {
			_ = n.sendProbe(nativeudp.ExtendedProbe{Size: size, Generation: generation})
			n.stats.sizeProbes.Add(1)
		}
		roundAt, roundEnd, roundWait = now, now.Add(max(2*srtt, nativeAnswerWait)), false
	}
	// endRound runs when every probe of the round is answered or the round
	// is due. The limit found is announced by a probe at once.
	endRound := func(now time.Time) {
		roundAt = time.Time{}
		if !search.End() {
			if n.up.Load() {
				sendRound(now)
			} else {
				roundWait = true
			}
			return
		}
		found := search.Limit()
		if recovering {
			// After a move the route is another, and its limit may be lower.
			lower := rerouted
			recovering, rerouted = false, false
			if found > n.session.Limit() || lower && found < n.session.Limit() {
				announce, pendingLimit = found, found
				announceGeneration, announcements = generation, 0
				probe(now)
			} else {
				recoveryAt = now.Add(nativeRecoveryEvery)
			}
			return
		}
		announce = found
		n.session.SetLimit(announce)
		recoveryAt = now.Add(nativeRecoveryEvery)
		if announce < nativeudp.FloorWire {
			slog.Info("Native UDP path is narrower than the smallest QUIC packet to an IPv6 address",
				"limit", announce, "size_probes", search.Sent())
		} else {
			slog.Debug("Native UDP limit found", "limit", announce, "size_probes", search.Sent())
		}
		probe(now)
	}
	// best is the shortest of the recent round trips of the current route.
	best := func() time.Duration {
		var b time.Duration
		for _, s := range recent[:min(samples, nativeRouteSamples)] {
			if b == 0 || s < b {
				b = s
			}
		}
		return b
	}
	// seeking reports whether a candidate may go once its time comes: the
	// search is not over, the path and its limit are settled, the server
	// proves routes, and a candidate could beat the route at all.
	seeking := func(now time.Time) bool {
		return candidate == nil && !awaiting && !n.stats.routeMoved.Load() && n.stats.routeCandidates.Load() < uint64(n.candidates) &&
			n.proves.Load() && n.server.Load() == serverSizes && n.up.Load() && n.hears(n.clock(now)) && active(now) &&
			unanswered == 0 && announce != 0 && roundAt.IsZero() && !roundWait && pendingLimit == 0 && !recovering &&
			best() > nativeRouteGain
	}
	// routeAt is when the search or the move takes its next step, if it has
	// one; the echo is wait's.
	routeAt := func(now time.Time) (time.Time, bool) {
		switch {
		case !drainAt.IsZero():
			return drainAt, true
		case candidate != nil:
			return n.epoch.Add(time.Duration(candidateAt-1) + need), true
		case !seeking(now):
			return time.Time{}, false
		}
		at := started.Add(nativeRouteAfter)
		if next := lastCandidate.Add(nativeRouteEvery); !lastCandidate.IsZero() && next.After(at) {
			at = next
		}
		if c := n.challengeAt.Load(); c != 0 {
			if next := n.epoch.Add(time.Duration(c-1) + nativeChallengeEvery); next.After(at) {
				at = next
			}
		}
		return at, true
	}
	routeStep := func(now time.Time) {
		switch {
		case !echoDue.IsZero():
			// The native datagrams sent by the old socket have reached the
			// server by now. From here the new socket is the path's.
			echoDue, lastProbe = time.Time{}, now
			n.echoAt.Store(n.clock(now))
			_ = n.sendProbe(nativeudp.ExtendedProbe{RouteEcho: true, RouteToken: token})
		case !drainAt.IsZero():
			n.retire(retired)
			retired, drainAt = nil, time.Time{}
		case candidate != nil:
			slog.Debug("Native UDP candidate route is no faster", "conn", n.logID, "candidate", n.stats.routeCandidates.Load())
			n.retire(candidate)
			candidate = nil
		case seeking(now):
			lastCandidate = now
			k := n.stats.routeCandidates.Add(1)
			c, err := n.dial()
			if err != nil {
				slog.Debug("Native UDP candidate route not opened", "conn", n.logID, "candidate", k, "error", err)
				return
			}
			s := &nativeSocket{datagramConn: c}
			if !n.listen(s) {
				return
			}
			before = best()
			need = before - max(nativeRouteGain, before*nativeRouteShare/100)
			candidateAt = n.clock(now)
			// An ordinary probe from an address the server does not know: its
			// challenge comes back a round trip of the new route later.
			if err := n.session.SealWriteExtendedProbe(nativeudp.ExtendedProbe{Limit: announce, Generation: announceGeneration, RouteProof: true},
				func(w []byte) error { return writeOn(s, w) }); err != nil {
				n.retire(s)
				return
			}
			candidate = s
		}
	}
	// The timer is set for a probe unless one of these says otherwise.
	toTell, toSearch, toRecover, toRoute := false, false, false, false
	wait := func(now time.Time) time.Duration {
		toTell, toSearch, toRecover = false, false, false
		// A winner's echo is the next probe of the path.
		if toRoute = !echoDue.IsZero(); toRoute {
			return echoDue.Sub(now)
		}
		next := nextProbe(now)
		at, ok := deafening(now)
		toTell = ok && at.After(now) && at.Before(next)
		if toTell {
			next = at
		}
		toSearch = !roundAt.IsZero() && roundEnd.Before(next)
		if toSearch {
			next, toTell = roundEnd, false
		}
		toRecover = !recoveryAt.IsZero() && roundAt.IsZero() && !roundWait && pendingLimit == 0 &&
			candidate == nil && !awaiting && n.up.Load() && n.recoverySupported.Load() && n.session.Limit() < nativeudp.MaxWire-8 &&
			recoveries < nativeRecoverySearches && recoveryAt.Before(next)
		if toRecover {
			next, toTell, toSearch = recoveryAt, false, false
		}
		if at, ok := routeAt(now); ok && at.Before(next) {
			next, toRoute, toTell, toSearch, toRecover = at, true, false, false, false
		}
		return next.Sub(now)
	}
	missed := func(now time.Time) bool {
		return missedProbeWindow(unanswered, firstSent, now)
	}
	// lost runs before every probe, not only on the timer: under traffic a
	// poke probes first and the timer never fires. The probe that follows
	// tells the server.
	lost := func(now time.Time) bool {
		if !n.up.Load() || !missed(now) {
			return false
		}
		n.up.Store(false)
		slog.Warn("Native UDP path lost; association using 0x83", "conn", n.logID, "unanswered_probes", unanswered,
			"probe_write_errors", n.stats.probeWriteErrors.Load()-probeErrorBaseline)
		n.flow.NativeLost(unanswered)
		strayUntil = lastProbe.Add(nativeStrayFor)
		unanswered, retry = 0, nativeRetryFirst
		if awaiting && retired != nil {
			// The new route went silent before the server answered there. The
			// path stays on it, and the answers go by TCP once told.
			n.retire(retired)
			retired = nil
		}
		return true
	}

	probe(time.Now())
	t := time.NewTimer(wait(time.Now()))
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-n.acked:
			now := time.Now()
			// The echo's answer is a round trip, and so is a lone probe's once
			// no late answer to a probe the count dropped could pass for it,
			// or when it is the first: the rounds of the search wait on it.
			// Until then a lone answer may only lengthen srtt, since a late
			// answer passes for a shorter round trip, never a longer one.
			sample, lone := now.Sub(lastProbe), unanswered == 1
			echo := false
			if rtt := n.echoRTT.Swap(0); rtt != 0 {
				sample, echo = time.Duration(rtt), true
			}
			switch {
			case echo || (lone && (srtt == 0 || !now.Before(strayUntil))):
				if srtt == 0 {
					srtt = sample
				} else {
					srtt += (sample - srtt) / 8
				}
				recent[samples%nativeRouteSamples] = sample
				samples++
				n.flow.NativeProbe(sample)
			case lone && sample > srtt:
				srtt += (sample - srtt) / 8
			}
			if unanswered > 1 {
				strayUntil = lastProbe.Add(nativeStrayFor)
			}
			unanswered = 0
			n.deafAt.Store(math.MaxInt64)
			retry = nativeRetryFirst
			if !n.up.Swap(true) {
				if verified {
					slog.Info("Native UDP path restored", "conn", n.logID)
					n.flow.NativeRestored()
				} else {
					slog.Info("Native UDP verified for association", "conn", n.logID)
					n.flow.NativeVerified(n.current().LocalAddr(), n.current().RemoteAddr())
				}
				verified = true
			}
			// The server answers by TCP until a probe says the client hears
			// it, and an application that only listens sends nothing else
			// that would say so.
			if n.told.Load() {
				probe(time.Now())
			}
			if n.server.Load() == serverSizes && (search == nil || roundWait) {
				if search == nil {
					search = nativeudp.NewSearch(n.draw)
				}
				sendRound(time.Now())
			}
			if awaiting && echoDue.IsZero() && !n.moving.Load() {
				// The server answered on the new socket, so it moved there.
				// The limit of the new route is searched with a generation of
				// its own; the one before holds until the server confirms.
				awaiting = false
				n.stats.routeMoved.Store(true)
				if retired != nil {
					drainAt = now.Add(nativeRouteDrain)
				}
				k := n.stats.routeCandidates.Load()
				slog.Info("Native UDP moved to a faster route", "conn", n.logID,
					"rtt_before", before.Round(100*time.Microsecond).String(), "rtt_after", after.Round(100*time.Microsecond).String(), "candidate", k)
				n.flow.NativeMoved(before, after, int(k))
				if n.recoverySupported.Load() && roundAt.IsZero() && pendingLimit == 0 {
					generation++
					recovering, rerouted = true, true
					search = nativeudp.NewSearch(n.draw)
					sendRound(time.Now())
				}
			}
		case answer := <-n.sized:
			if recovering && answer.Generation != generation {
				break
			}
			size := answer.Size
			if roundAt.IsZero() {
				break
			}
			now := time.Now()
			control, all := search.Answered(size)
			if control {
				r := now.Sub(roundAt)
				roundEnd = roundAt.Add(max(2*r, r+nativeSearchSlack))
			}
			if all {
				endRound(now)
			}
		case answer := <-n.limitACK:
			if pendingLimit != 0 && answer.Generation == announceGeneration && answer.Limit == pendingLimit {
				if n.session.ApplyProbeLimit(nativeudp.ExtendedProbe{Generation: answer.Generation, Limit: answer.Limit}) {
					slog.Info("Native UDP limit agreed", "conn", n.logID, "limit", answer.Limit, "generation", answer.Generation)
				}
				pendingLimit = 0
				recoveryAt = time.Now().Add(nativeRecoveryEvery)
			}
		case c := <-n.challenges:
			if c.s != candidate {
				break
			}
			rtt := time.Duration(c.at - candidateAt)
			if rtt > need || !n.up.Load() {
				n.retire(candidate)
				candidate = nil
				break
			}
			// The candidate won. The application's datagrams go by 0x83 until
			// the server answers on it, and nothing more leaves the old
			// socket: the echo waits a round trip of the old route, by which
			// its native datagrams have reached the server.
			n.carrying.Lock()
			retired = n.conn.Swap(candidate)
			n.moving.Store(true)
			n.carrying.Unlock()
			after, token, candidate, awaiting = rtt, c.token, nil, true
			echoDue = time.Now().Add(srtt)
			// The liveness of the new route starts afresh: the answers to the
			// probes of the old one stay on its socket.
			srtt, unanswered, strayUntil = 0, 0, time.Time{}
		case <-n.poked:
			if now := time.Now(); n.up.Load() && now.Sub(lastProbe) >= nativeActiveEvery {
				lost(now)
				probe(now)
			}
		case <-t.C:
			now := time.Now()
			if toRoute {
				routeStep(now)
				break
			}
			if toRecover {
				recoveries++
				generation++
				recovering = true
				search = nativeudp.NewSearch(n.draw)
				sendRound(now)
				break
			}
			if toSearch {
				endRound(now)
				break
			}
			if toTell {
				if _, ok := deafening(now); ok && !n.hears(n.clock(now)) {
					n.tell(false)
				}
				break
			}
			if !lost(now) && !n.up.Load() {
				retry = min(2*retry, nativeRetryMax)
				// Behind a front on another host the probes reach nothing,
				// and nothing else would say where they went.
				if !verified && !reported && missed(now) {
					reported = true
					slog.Info("Native UDP not answering; association using 0x83", "conn", n.logID,
						"addr", n.current().RemoteAddr().String(), "unanswered_probes", unanswered)
				}
			}
			probe(now)
		}
		t.Reset(wait(time.Now()))
	}
}

func missedProbeWindow(unanswered int, firstSent, now time.Time) bool {
	return unanswered >= nativeMisses && now.Sub(firstSent) >= nativeMissSpan
}
