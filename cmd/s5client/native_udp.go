package main

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
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
// address the tunnel reached, with the keys of the tunnel.
func dialNative(tunnel net.Conn, port uint16) (*nativeClient, *net.UDPConn, error) {
	keys, err := obfs.DatagramKeysOf(tunnel)
	if err != nil {
		return nil, nil, err
	}
	host, _, err := net.SplitHostPort(tunnel.RemoteAddr().String())
	if err != nil {
		return nil, nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, nil, err
	}
	c, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, nil, err
	}
	n := newNativeClient(c, nativeudp.NewSession(keys), nil)
	n.writer = socks5.NewTunnelWriter(tunnel, n.signalFrame, nil)
	n.signal = n.writer.Control
	return n, c, nil
}

// datagramConn is the client's connected UDP socket to the server's native
// port.
type datagramConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
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
	conn    datagramConn
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
	poked  chan struct{}
	stats  nativeStats
}

// nativeStats is where the datagrams of the association went, for the line
// that logs its end: delivery alone does not say which path carried them.
type nativeStats struct {
	sent, sentOversize, sentTCP atomic.Uint64
	received, receivedTCP       atomic.Uint64
}

func (n *nativeClient) logStats() []any {
	var dropped uint64
	if n.writer != nil {
		dropped = n.writer.Dropped()
	}
	return []any{"native_sent", n.stats.sent.Load(), "tcp_sent_oversize", n.stats.sentOversize.Load(),
		"tcp_sent_other", n.stats.sentTCP.Load(), "native_received", n.stats.received.Load(),
		"tcp_received", n.stats.receivedTCP.Load(), "tunnel_drops", dropped}
}

var heardProbe = []byte{nativeudp.ProbeHeard}

func newNativeClient(conn datagramConn, session *nativeudp.Session, signal func()) *nativeClient {
	n := &nativeClient{conn: conn, session: session, signal: signal, jitter: rand.Float64,
		acked: make(chan struct{}, 1), poked: make(chan struct{}, 1)}
	n.told.Store(true)
	n.deafAt.Store(math.MaxInt64)
	return n
}

func (n *nativeClient) send(kind byte, payload []byte) error {
	return n.session.SealWrite(kind, payload, func(wire []byte) error {
		_, err := n.conn.Write(wire)
		return err
	})
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

// carry sends d natively and reports whether it did. A datagram it refuses is
// the caller's to send by 0x83.
func (n *nativeClient) carry(d []byte) bool {
	now := time.Now().UnixNano()
	n.used(now)
	if len(d) > n.session.MaxPayload() {
		n.stats.sentOversize.Add(1)
		return false
	}
	if !n.up.Load() {
		n.stats.sentTCP.Add(1)
		return false
	}
	// Up but not heard lately: the association just woke from idle, or the
	// path is failing. The answers go by TCP until the probe answers which,
	// and nothing is logged.
	if !n.hears(now) {
		n.tell(false)
		n.poke()
		n.stats.sentTCP.Add(1)
		return false
	}
	if n.send(nativeudp.KindData, d) != nil {
		n.poke()
		n.stats.sentTCP.Add(1)
		return false
	}
	n.stats.sent.Add(1)
	n.told.Store(false)
	if !n.usedData.Swap(true) {
		slog.Info("Native UDP carrying application datagrams")
	}
	return true
}

// tcpAnswer records a datagram of the server that came by TCP. One native
// could carry, while the client has not told the server to use TCP, is the
// server not knowing that the client hears it: its heard probe was lost, or
// arrived before a loss signal it outranks. The association counts as active
// then, so the next probe says ProbeHeard within one active interval rather
// than at the idle keepalive.
func (n *nativeClient) tcpAnswer(size int) {
	n.stats.receivedTCP.Add(1)
	if n.up.Load() && !n.told.Load() && size <= n.session.MaxPayload() {
		n.used(time.Now().UnixNano())
	}
}

// run reads the native socket until it is closed and probes the path while it
// does. deliver gets the server's datagrams.
func (n *nativeClient) run(deliver func([]byte)) {
	done := make(chan struct{})
	defer close(done)
	go n.watch(done)
	var b [nativeudp.MaxWire + 1]byte
	failed := false
	for {
		r, err := n.conn.Read(b[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
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
			continue
		}
		now := time.Now().UnixNano()
		n.lastSeen.Store(now)
		switch p.Kind {
		case nativeudp.KindProbeAck:
			select {
			case n.acked <- struct{}{}:
			default:
			}
		case nativeudp.KindData:
			n.used(now)
			n.stats.received.Add(1)
			deliver(p.Data)
		}
	}
}

// watch owns the probes: when they go out, and what their answers mean.
func (n *nativeClient) watch(done <-chan struct{}) {
	var (
		unanswered int
		firstSent  time.Time
		lastProbe  time.Time
		draw       float64 // drawn per probe, so recomputing the wait does not redraw it
		retry      = nativeRetryFirst
		verified   bool
		reported   bool          // a path never heard was logged
		srtt       time.Duration // of probes answered while alone, 0 before the first
	)
	active := func(now time.Time) bool { return now.UnixNano()-n.lastUsed.Load() < int64(nativeActiveFor) }
	probe := func(now time.Time) {
		heard := n.hears(now.UnixNano())
		switch {
		case verified && !n.up.Load():
			// A path lost after it was verified tells the server with every
			// retry until it is back: a native datagram sent just before the
			// loss can arrive after the first signal and turn the answers
			// back to the dead path.
			n.tell(true)
		case !heard && active(now):
			// An active association that stopped hearing the server: the
			// answers go by TCP now, not once the path is found lost.
			n.tell(false)
		}
		var payload []byte
		if heard {
			payload = heardProbe
			n.told.Store(false)
		}
		_ = n.send(nativeudp.KindProbe, payload)
		if unanswered == 0 {
			firstSent = now
		}
		unanswered++
		if unanswered == 2 {
			n.deafAt.Store(now.Add(max(nativeAnswerWait, 2*srtt)).UnixNano())
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
		return time.Unix(0, at), true
	}
	toTell := false // the timer is set for deafening, not for a probe
	wait := func(now time.Time) time.Duration {
		next := nextProbe(now)
		at, ok := deafening(now)
		toTell = ok && at.After(now) && at.Before(next)
		if toTell {
			next = at
		}
		return next.Sub(now)
	}
	missed := func(now time.Time) bool {
		return unanswered >= nativeMisses && now.Sub(firstSent) >= nativeMissSpan
	}
	// lost runs before every probe, not only on the timer: under traffic a
	// poke probes first and the timer never fires. The probe that follows
	// tells the server.
	lost := func(now time.Time) bool {
		if !n.up.Load() || !missed(now) {
			return false
		}
		n.up.Store(false)
		slog.Warn("Native UDP path lost; association using 0x83", "unanswered_probes", unanswered)
		unanswered, retry = 0, nativeRetryFirst
		return true
	}

	probe(time.Now())
	t := time.NewTimer(wait(time.Now()))
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-n.acked:
			now := time.Now()
			// Only the answer to a probe that went out alone says which probe
			// it answers.
			if unanswered == 1 {
				if sample := now.Sub(lastProbe); srtt == 0 {
					srtt = sample
				} else {
					srtt += (sample - srtt) / 8
				}
			}
			unanswered = 0
			n.deafAt.Store(math.MaxInt64)
			retry = nativeRetryFirst
			if !n.up.Swap(true) {
				if verified {
					slog.Info("Native UDP path restored")
				} else {
					slog.Info("Native UDP verified for association")
				}
				verified = true
			}
			// The server answers by TCP until a probe says the client hears
			// it, and an application that only listens sends nothing else
			// that would say so.
			if n.told.Load() {
				probe(time.Now())
			}
		case <-n.poked:
			if now := time.Now(); n.up.Load() && now.Sub(lastProbe) >= nativeActiveEvery {
				lost(now)
				probe(now)
			}
		case <-t.C:
			now := time.Now()
			if toTell {
				if _, ok := deafening(now); ok && !n.hears(now.UnixNano()) {
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
					slog.Info("Native UDP not answering; association using 0x83",
						"addr", n.conn.RemoteAddr().String(), "unanswered_probes", unanswered)
				}
			}
			probe(now)
		}
		t.Reset(wait(time.Now()))
	}
}
