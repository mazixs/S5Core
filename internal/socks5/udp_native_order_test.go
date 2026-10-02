package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stalledConn is the server's end of a control connection whose writes can be
// held, as a full send buffer holds them.
type stalledConn struct {
	net.Conn
	stall   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (c *stalledConn) Write(p []byte) (int, error) {
	if c.stall.Load() {
		select {
		case c.started <- struct{}{}:
		default:
		}
		<-c.release
	}
	return c.Conn.Write(p)
}

// An answer too big for native waits for the stream, and a short answer
// behind it goes native at once. The reader of the answers used to write the
// big one itself, and every answer after it waited for the stream too
// (finding F1 of docs/reports/v2.3-rc1-audit-2026-09-26.md).
func TestAShortAnswerGoesNativeWhileTheStreamIsStalled(t *testing.T) {
	native := newScriptedNative()
	server, err := New(&Config{Logger: slog.New(slog.DiscardHandler),
		NativeUDP: func(net.Conn) (NativeAssociation, error) { return native, nil }})
	if err != nil {
		t.Fatal(err)
	}
	client, other := net.Pipe()
	stalled := &stalledConn{Conn: other, started: make(chan struct{}, 1), release: make(chan struct{})}
	defer client.Close()
	defer other.Close()
	go func() { _ = server.ServeConnContext(context.Background(), stalled) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _, _ = client.Write([]byte{5, 1, 0, 5, UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}) }()
	var reply [12]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	native.in <- scriptedDatagram{data: BuildUDPHeader(&AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: target.LocalAddr().(*net.UDPAddr).Port}, []byte("hello"))}
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [2048]byte
	_, relay, err := target.ReadFromUDPAddrPort(b[:])
	if err != nil {
		t.Fatal(err)
	}

	stalled.stall.Store(true)
	if _, err := target.WriteToUDPAddrPort(make([]byte, 1400), relay); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled.started:
	case <-time.After(time.Second):
		t.Fatal("the big answer did not reach the stream")
	}
	if _, err := target.WriteToUDPAddrPort([]byte("short"), relay); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-native.sent:
		if !strings.HasSuffix(string(answer), "short") {
			t.Fatalf("native answer %q", answer)
		}
	case <-time.After(time.Second):
		t.Fatal("the short answer waited for the stalled stream")
	}
	close(stalled.release)
	if answer := readTCPAnswer(t, client); len(answer) < 1400 {
		t.Fatalf("TCP answer of %d bytes, want the big one", len(answer))
	}
}

// signalLoss writes the client's empty frame with next and reads the server's
// answer to it.
func signalLoss(t *testing.T, native *scriptedNative, conn net.Conn, next uint64) {
	t.Helper()
	if _, err := conn.Write(binary.BigEndian.AppendUint64([]byte{0, 0}, next)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-native.resynced:
	case <-time.After(3 * time.Second):
		t.Fatal("the loss signal did not reach the native path")
	}
	var answer [10]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		t.Fatalf("no answer to the loss signal: %v", err)
	}
}

// answersGo writes one answer to the client and reports whether it went
// native.
func answersGo(t *testing.T, native *scriptedNative, target *net.UDPConn, relay netip.AddrPort, conn net.Conn, word string) bool {
	t.Helper()
	if _, err := target.WriteToUDPAddrPort([]byte(word), relay); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-native.sent:
		if !strings.HasSuffix(string(answer), word) {
			t.Fatalf("native answer %q, want %q", answer, word)
		}
		return true
	case <-time.After(300 * time.Millisecond):
	}
	if answer := readTCPAnswer(t, conn); !strings.HasSuffix(string(answer), word) {
		t.Fatalf("TCP answer %q, want %q", answer, word)
	}
	return false
}

// A loss signal decided before a native datagram the server already has is
// older news, however late it comes: TCP and UDP deliver in either order. It
// used to take the answers to TCP until the next heard probe, which a lost
// one could put off for good (finding F2).
func TestALateLossSignalDoesNotOverruleANewerNativeDatagram(t *testing.T) {
	native := newScriptedNative()
	target, relay, conn := nativeAnswers(t, native)
	native.in <- scriptedDatagram{counter: 9, data: BuildUDPHeader(&AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: target.LocalAddr().(*net.UDPAddr).Port}, []byte("newer"))}
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [64]byte
	if _, _, err := target.ReadFromUDPAddrPort(b[:]); err != nil {
		t.Fatal(err)
	}

	signalLoss(t, native, conn, 5)
	if !answersGo(t, native, target, relay, conn, "after-late-signal") {
		t.Fatal("a signal decided before datagram 9 took the answers to TCP")
	}
	signalLoss(t, native, conn, 10)
	if answersGo(t, native, target, relay, conn, "after-new-signal") {
		t.Fatal("a signal decided after datagram 9 left the answers native")
	}
}

// A heard probe sealed before the latest loss signal was decided does not
// bring the answers back, and one sealed after it does.
func TestAHeardProbeOlderThanTheLossSignalChangesNothing(t *testing.T) {
	native := newScriptedNative()
	target, relay, conn := nativeAnswers(t, native)
	signalLoss(t, native, conn, 5)

	native.hear(t, 3)
	if answersGo(t, native, target, relay, conn, "after-old-probe") {
		t.Fatal("a probe sealed before the loss signal took the answers native")
	}
	native.hear(t, 5)
	if !answersGo(t, native, target, relay, conn, "after-new-probe") {
		t.Fatal("a probe sealed after the loss signal left the answers on TCP")
	}
}

// The counters say which path each datagram of the association took and why
// the answers moved, so that the path is read off the server rather than
// guessed from delivery (priority 4 of the 2.3.0-rc1 audit).
func TestTheCountersSayWhichPathEachDatagramTook(t *testing.T) {
	counters := new(NativeCounters)
	native := newScriptedNative(errors.New("no buffer space"))
	target, relay, conn := nativeAnswersCounted(t, native, counters)
	targetAddr := &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: target.LocalAddr().(*net.UDPAddr).Port}

	if answersGo(t, native, target, relay, conn, "failed") {
		t.Fatal("the answer the native path failed went native")
	}
	if !answersGo(t, native, target, relay, conn, "native") {
		t.Fatal("the answer after a failed one did not go native")
	}
	if _, err := target.WriteToUDPAddrPort(make([]byte, 1400), relay); err != nil {
		t.Fatal(err)
	}
	if answer := readTCPAnswer(t, conn); len(answer) < 1400 {
		t.Fatalf("TCP answer of %d bytes, want the big one", len(answer))
	}
	signalLoss(t, native, conn, 5)
	if answersGo(t, native, target, relay, conn, "route") {
		t.Fatal("an answer after the loss signal went native")
	}
	signalLoss(t, native, conn, 0)
	native.hear(t, 3)

	var b [2048]byte
	for _, size := range []int{100, 1400} {
		datagram := BuildUDPHeader(targetAddr, make([]byte, size))
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(datagram)))
		if _, err := conn.Write(append(frame, datagram...)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := target.ReadFromUDPAddrPort(b[:]); err != nil {
			t.Fatalf("the client's TCP datagram of %d bytes: %v", size, err)
		}
	}

	want := map[string]uint64{
		"answers native": 1, "answers oversize": 1, "answers route": 1, "answers failed": 1,
		"client native": 1, "client oversize": 1, "client route": 1,
		"to native": 1, "to tcp": 1, "stale loss": 1, "stale heard": 1,
	}
	got := func() map[string]uint64 {
		c := counters
		return map[string]uint64{
			"answers native":   c.AnswersNative.Load(),
			"answers oversize": c.AnswersOversize.Load(),
			"answers route":    c.AnswersRoute.Load(),
			"answers failed":   c.AnswersFailed.Load(),
			"client native":    c.ClientNative.Load(),
			"client oversize":  c.ClientOversize.Load(),
			"client route":     c.ClientRoute.Load(),
			"to native":        c.ToNative.Load(),
			"to tcp":           c.ToTCP.Load(),
			"stale loss":       c.StaleLoss.Load(),
			"stale heard":      c.StaleHeard.Load(),
		}
	}
	deadline := time.Now().Add(time.Second)
	for !maps.Equal(got(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("counters %v, want %v", got(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// The record of a native association says what it carried by the native path,
// how often its answers left it and what its stream dropped, so that one line
// of the journal tells whether the path worked for that association alone
// (docs/plan/draft.md, Ч-30).
func TestTheRecordOfAnAssociationSaysWhatItCarriedNative(t *testing.T) {
	ended := make(chan *ConnEnd, 1)
	native := newScriptedNative()
	target, relay, conn := nativeAnswersWith(t, native, &Config{
		OnConnEnd: func(_ net.Conn, e *ConnEnd) { ended <- e },
	})
	if !answersGo(t, native, target, relay, conn, "native") {
		t.Fatal("the answer did not go native")
	}
	signalLoss(t, native, conn, 5)
	if answersGo(t, native, target, relay, conn, "route") {
		t.Fatal("an answer after the loss signal went native")
	}
	_ = conn.Close()

	select {
	case e := <-ended:
		if e.Command != AssociationNative || e.NativeUp != 1 || e.NativeDown != 1 || e.PathMoves != 1 || e.TunnelDrops != 0 {
			t.Fatalf("native up/down %d/%d, moves %d, drops %d, want 1/1, 1, 0",
				e.NativeUp, e.NativeDown, e.PathMoves, e.TunnelDrops)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the association never reported its end")
	}
}

// An association the client closes is a session that went well: it used to be
// counted as a failed one, so every healthy association was a failure in the
// session metric (docs/plan/draft.md, Ч-17).
func TestAnAssociationTheClientClosesIsASessionThatWentWell(t *testing.T) {
	type outcome struct{ ok bool }
	sessions := make(chan outcome, 1)
	native := newScriptedNative()
	_, _, conn := nativeAnswersWith(t, native, &Config{
		ObservePhase: func(p Phase, _ time.Duration, ok bool) {
			if p == PhaseSession {
				sessions <- outcome{ok}
			}
		},
	})
	_ = conn.Close()

	select {
	case o := <-sessions:
		if !o.ok {
			t.Fatal("an association closed by the client was counted as a failed session")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session phase never ended")
	}
}
