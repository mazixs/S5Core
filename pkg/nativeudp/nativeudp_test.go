package nativeudp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

func pair(t *testing.T) (*Session, *Session) {
	t.Helper()
	return pairOf(t, 9)
}

// pairOf is a pair of its own: sessions of pairs with another seed share no
// tags.
func pairOf(t *testing.T, seed byte) (*Session, *Session) {
	t.Helper()
	psk := bytes.Repeat([]byte{7}, 32)
	secret := bytes.Repeat([]byte{seed}, 40)
	client, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	return NewSession(client), NewSession(server)
}

func TestFixedTagMatchesHMAC(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	tagger := newTagger(key)
	for _, c := range []uint64{0, 1, 127, 65537, ^uint64(0)} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], c)
		h := hmac.New(sha256.New, key[:])
		_, _ = h.Write(b[:])
		if got, want := tagger.tag(c), h.Sum(nil)[:8]; !bytes.Equal(got[:], want) {
			t.Fatalf("counter %d: got %x want %x", c, got, want)
		}
	}
}

func TestLostOutOfOrderReplayAndForgery(t *testing.T) {
	client, server := pair(t)
	var wires [][]byte
	for i := 0; i < 8; i++ {
		wire, err := client.Seal(nil, KindData, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, wire)
	}
	for _, i := range []int{0, 3, 2, 7, 5} {
		p, err := server.Open(append([]byte(nil), wires[i]...))
		if err != nil || p.Kind != KindData || len(p.Data) != 1 || p.Data[0] != byte(i) {
			t.Fatalf("packet %d: %v %+v", i, err, p)
		}
		if _, err := server.Open(append([]byte(nil), wires[i]...)); err == nil {
			t.Fatalf("replay %d accepted", i)
		}
	}
	forged := append([]byte(nil), wires[1]...)
	forged[len(forged)-1] ^= 1
	if _, err := server.Open(forged); err == nil {
		t.Fatal("forgery accepted")
	}
	if _, err := server.Open(append([]byte(nil), wires[1]...)); err != nil {
		t.Fatalf("forgery claimed counter: %v", err)
	}
}

func TestRecoversAfterHighRateOutage(t *testing.T) {
	client, server := pair(t)
	// A 128 Hz game can send about 128 datagrams during the one-second
	// liveness timeout. Leave room for jitter, probes and higher tick rates.
	for i := 0; i < 400; i++ {
		if _, err := client.Seal(nil, KindData, []byte("lost")); err != nil {
			t.Fatal(err)
		}
	}
	wire, err := client.Seal(nil, KindProbe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := server.Open(wire); err != nil || p.Kind != KindProbe {
		t.Fatalf("cannot recover after 400 lost datagrams: %v %+v", err, p)
	}
}

// Past lookAhead datagrams lost in a row no tag matches again, and the
// peer's word for its next counter moves the window there. The resync moves
// only forward: a stale one does not reopen what was received.
func TestAResyncRecoversFromMoreLostThanTheWindow(t *testing.T) {
	client, server := pair(t)
	seal := func(kind byte) []byte {
		t.Helper()
		wire, err := client.Seal(nil, kind, []byte("tick"))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	first := seal(KindData)
	if _, err := server.Open(first); err != nil {
		t.Fatal(err)
	}
	var held []byte
	for i := 0; i < lookAhead+100; i++ {
		held = seal(KindData)
	}
	if _, err := server.Open(append([]byte(nil), seal(KindProbe)...)); err == nil {
		t.Fatal("a datagram past the window opened without a resync")
	}
	server.Resync(client.Next())
	probe := seal(KindProbe)
	if p, err := server.Open(append([]byte(nil), probe...)); err != nil || p.Kind != KindProbe {
		t.Fatalf("after the resync: %v %+v", err, p)
	}
	if _, err := server.Open(probe); err == nil {
		t.Fatal("a replay after the resync opened")
	}
	if _, err := server.Open(held); err != nil {
		t.Fatalf("a lost datagram just below the resync did not open: %v", err)
	}
	server.Resync(1)
	if _, err := server.Open(first); err == nil {
		t.Fatal("a stale resync reopened a received datagram")
	}
	if _, err := server.Open(seal(KindData)); err != nil {
		t.Fatalf("a stale resync moved the window back: %v", err)
	}
	// A jump far past the window costs a window of tags, not the jump.
	client.sendMu.Lock()
	client.send += 1 << 40
	client.sendMu.Unlock()
	server.Resync(client.Next())
	if _, err := server.Open(seal(KindData)); err != nil {
		t.Fatalf("after a resync far past the window: %v", err)
	}
}

// A resync through the hub keeps the hub's index in step with the window,
// and a second one within resyncEvery is ignored: each can cost a window of
// tags under the hub's lock.
func TestAResyncThroughTheHubKeepsItsIndexInStep(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	c := dialHub(t, hub)
	probe := func() {
		t.Helper()
		wire, err := client.Seal(nil, KindProbe, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	answered := func() {
		t.Helper()
		probe()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [MaxWire]byte
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal("the probe after the resync was not answered:", err)
		}
		if p, err := client.Open(b[:n]); err != nil || p.Kind != KindProbeAck {
			t.Fatalf("answer: %v %+v", err, p)
		}
	}
	dropped := func(drops uint64) {
		t.Helper()
		probe()
		waitFor(t, hub, func(s Stats) bool { return s.TagDrops == drops })
	}
	lose := func() {
		t.Helper()
		for i := 0; i < 2*window; i++ {
			if _, err := client.Seal(nil, KindData, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	lose()
	dropped(1)
	hub.Resync(registered, client.Next())
	answered()
	lose()
	// Under -race on a loaded machine answered and lose outlast resyncEvery,
	// and the second resync is then rightly honoured: take the last one to
	// have been just now.
	hub.mu.Lock()
	if registered.resynced.IsZero() {
		hub.mu.Unlock()
		t.Fatal("the resync did not record when it happened")
	}
	registered.resynced = time.Now()
	hub.mu.Unlock()
	hub.Resync(registered, client.Next())
	dropped(2)
	hub.mu.Lock()
	registered.resynced = registered.resynced.Add(-resyncEvery)
	hub.mu.Unlock()
	hub.Resync(registered, client.Next())
	answered()
	hub.mu.Lock()
	registered.recvMu.Lock()
	inWindow := registered.recvTop - low(registered.recvHigh)
	live, index, spent := len(registered.recvTags), len(hub.index), len(hub.spent)
	registered.recvMu.Unlock()
	hub.mu.Unlock()
	if inWindow != window || live != index || index+spent > window {
		t.Fatalf("window %d, session tags %d, hub tags %d live and %d spent", inWindow, live, index, spent)
	}
	hub.Remove(registered)
	if len(hub.index) != 0 || len(hub.spent) != 0 {
		t.Fatalf("session tags left in hub: live=%d spent=%d", len(hub.index), len(hub.spent))
	}
}

func TestHubProbeAndData(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wire, _ := client.Seal(nil, KindProbe, nil)
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [MaxWire]byte
	n, err := c.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err := client.Open(b[:n])
	if err != nil || p.Kind != KindProbeAck {
		t.Fatalf("probe: %v %+v", err, p)
	}
	wire, _ = client.Seal(nil, KindData, []byte("game"))
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case p = <-registered.Packets():
		if string(p.Data) != "game" {
			t.Fatalf("data %q", p.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("hub did not deliver data")
	}
	if err := hub.Send(registered, KindData, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err = client.Open(b[:n])
	if err != nil || string(p.Data) != "reply" {
		t.Fatalf("reply: %v %+v", err, p)
	}
}

// Every probe is answered, and only one that says the client hears the
// server reaches the association: a bare probe asks whether the path works,
// and the client sends those on a path it just lost.
func TestOnlyAHeardProbeReachesTheAssociation(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c := dialHub(t, hub)
	probe := func(payload []byte) {
		t.Helper()
		wire, _ := client.Seal(nil, KindProbe, payload)
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [MaxWire]byte
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		if p, err := client.Open(b[:n]); err != nil || p.Kind != KindProbeAck {
			t.Fatalf("probe %x: %v %+v", payload, err, p)
		}
	}
	for _, payload := range [][]byte{nil, {0}, {ProbeHeard, 0}, {2}} {
		probe(payload)
	}
	select {
	case <-registered.Heard():
		t.Fatal("a probe that does not hear the server reached the association")
	case <-time.After(50 * time.Millisecond):
	}
	probe([]byte{ProbeHeard})
	select {
	case <-registered.Heard():
	case <-time.After(time.Second):
		t.Fatal("a heard probe did not reach the association")
	}
	if len(registered.Packets()) != 0 {
		t.Fatal("a probe was delivered as a datagram")
	}
}

// A heard probe and a datagram carry the client's counter to the association,
// which places its loss signals by them (docs/veil-spec.md, 10.6). Heard
// probes that coalesce keep the highest.
func TestTheAssociationLearnsTheCountersOfTheClientsWords(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c := dialHub(t, hub)
	send := func(kind byte, payload []byte) uint64 {
		t.Helper()
		counter := client.Next()
		wire, _ := client.Seal(nil, kind, payload)
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
		return counter
	}
	send(KindProbe, []byte{ProbeHeard})
	second := send(KindProbe, []byte{ProbeHeard})
	<-registered.Heard()
	for deadline := time.Now().Add(time.Second); registered.HeardCounter() != second; {
		if time.Now().After(deadline) {
			t.Fatalf("heard counter %d, want the later probe's %d", registered.HeardCounter(), second)
		}
		time.Sleep(time.Millisecond)
	}
	data := send(KindData, []byte("datagram"))
	select {
	case p := <-registered.Packets():
		if p.Counter != data {
			t.Fatalf("datagram counter %d, want %d", p.Counter, data)
		}
		p.Release()
	case <-time.After(time.Second):
		t.Fatal("the datagram did not reach the association")
	}
}

// waitFor polls the hub until its counters satisfy done.
func waitFor(t *testing.T, hub *Hub, done func(Stats) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !done(hub.Stats()) {
		if time.Now().After(deadline) {
			t.Fatalf("hub counters: %+v", hub.Stats())
		}
		time.Sleep(time.Millisecond)
	}
}

func dialHub(t *testing.T, hub *Hub) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func portOf(c *net.UDPConn) uint16 { return uint16(c.LocalAddr().(*net.UDPAddr).Port) }

// The answers follow a new address only once it has sent the newest datagram
// twice in a row. An observer that forwards a copy from its own address ahead
// of the original, or a datagram it held back, used to take the answers of
// the association, and with a forged source it could point them anywhere
// (finding 11 of the 2.3 review). A client whose NAT mapping changed moves
// with its second datagram.
func TestTheAnswersFollowANewAddressOnlyWhenItLeads(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	peerIs := func(want *net.UDPConn, when string) {
		t.Helper()
		if peer, ok := registered.Peer(); !ok || peer.Port() != portOf(want) {
			t.Fatalf("%s: answers go to %v, want port %d", when, peer, portOf(want))
		}
	}
	seal := func(kind byte) []byte {
		wire, err := client.Seal(nil, kind, []byte("state"))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	send := func(c *net.UDPConn, wire []byte) {
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	origin, observer := dialHub(t, hub), dialHub(t, hub)
	send(origin, seal(KindData))
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 1 })
	peerIs(origin, "first datagram")

	// A copy that outran its original.
	copied := seal(KindData)
	send(observer, copied)
	send(origin, copied)
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 2 && s.ReplayDrops == 1 })
	peerIs(origin, "a copy ahead of the original")
	send(origin, seal(KindData))
	send(observer, seal(KindData))
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 4 })
	peerIs(origin, "a copy ahead of the original, once more")

	// A datagram held back and sent after a newer one.
	held, newer := seal(KindData), seal(KindData)
	send(origin, newer)
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 5 })
	send(observer, held)
	send(observer, seal(KindData))
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 7 })
	peerIs(origin, "a held-back datagram and a copy")

	// A forged datagram does not count at all.
	forged := seal(KindData)
	forged[len(forged)-1] ^= 1
	send(observer, forged)
	waitFor(t, hub, func(s Stats) bool { return s.AuthDrops == 1 })
	peerIs(origin, "a forged datagram")

	// A new mapping: the first probe is answered where the answers went, the
	// second one moves them.
	rebound := dialHub(t, hub)
	send(rebound, seal(KindProbe))
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 8 })
	peerIs(origin, "one probe from a new address")
	send(rebound, seal(KindProbe))
	_ = rebound.SetReadDeadline(time.Now().Add(time.Second))
	var b [MaxWire]byte
	n, err := rebound.Read(b[:])
	if err != nil {
		t.Fatalf("the second probe from the new address: %v", err)
	}
	if p, err := client.Open(b[:n]); err != nil || p.Kind != KindProbeAck {
		t.Fatalf("answer %+v, %v", p, err)
	}
	peerIs(rebound, "two probes from a new address")
}

// A write the hub cannot finish, a full socket buffer say, stalls the one
// that writes, not the reader: the answer to a probe used to be written by
// the reader itself, and every session of the node stopped receiving until
// the write went through (finding 4 of review 3 in
// docs/plan/native-udp-review.md).
func TestAStalledAnswerDoesNotStopTheOtherSessions(t *testing.T) {
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	release := make(chan struct{})
	stalled := make(chan struct{}, 1)
	write := hub.write
	hub.write = func(wire, oob []byte, to netip.AddrPort) error {
		select {
		case stalled <- struct{}{}:
			<-release
		default:
		}
		return write(wire, oob, to)
	}
	defer close(release)
	probing, probed := pairOf(t, 9)
	sending, sent := pairOf(t, 10)
	a, b := hub.Register(probed.keys), hub.Register(sent.keys)
	defer hub.Remove(a)
	defer hub.Remove(b)
	c := dialHub(t, hub)
	wire, _ := probing.Seal(nil, KindProbe, nil)
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("the answer to the probe was not written")
	}
	wire, _ = sending.Seal(nil, KindData, []byte("game"))
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-b.Packets():
		p.Release()
	case <-time.After(time.Second):
		t.Fatal("a stalled answer stopped the other sessions")
	}
}

func TestHubStatsClassifyDropsAndBoundSessions(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	session := hub.Register(server.keys)
	defer hub.Remove(session)
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first, _ := client.Seal(nil, KindData, []byte("first"))
	second, _ := client.Seal(nil, KindData, []byte("second"))
	forged := append([]byte(nil), second...)
	forged[len(forged)-1] ^= 1
	unknown := append([]byte(nil), first...)
	unknown[0] ^= 1
	for _, wire := range [][]byte{first, first, unknown, forged, second} {
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		st := hub.Stats()
		if st.Accepted == 2 && st.ReplayDrops == 1 && st.TagDrops == 1 && st.AuthDrops == 1 {
			if st.Active != 1 {
				t.Fatalf("active sessions: %+v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("incorrect packet classification: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
	hub.Remove(session)
	if st := hub.Stats(); st.Active != 0 {
		t.Fatalf("session removal: %+v", st)
	}
	if len(hub.index) != 0 || len(hub.spent) != 0 {
		t.Fatalf("session tags left in hub: live=%d spent=%d", len(hub.index), len(hub.spent))
	}
}

// A datagram through the hub and its answer allocate nothing: the wire
// buffers come from a pool, and the window moves without new map entries or
// a copy of the peer's address (finding 5 of the 2.3 review). Both used to
// cost an allocation per datagram, and the codec benchmark did not see them.
func TestADatagramThroughTheHubCostsNoAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops pooled buffers")
	}
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c := dialHub(t, hub)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	payload := bytes.Repeat([]byte{5}, 200)
	write := func(wire []byte) error { _, err := c.Write(wire); return err }
	var b [MaxWire]byte
	roundTrip := func() {
		if err := client.SealWrite(KindData, payload, write); err != nil {
			t.Fatal(err)
		}
		p := <-registered.Packets()
		p.Release()
		if err := hub.Send(registered, KindData, payload); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Open(b[:n]); err != nil {
			t.Fatal(err)
		}
	}
	roundTrip()
	if got := testing.AllocsPerRun(2000, roundTrip); got != 0 {
		t.Errorf("one datagram each way through the hub allocates %.1f times, want 0", got)
	}
}

// The window moves by counter: after thousands of datagrams, lost and out of
// order, a session holds exactly the tags of its window and the hub holds
// them and nothing else. A counter below the window is refused, and a replay
// inside it is told apart from an unknown tag.
func TestTheWindowStaysTheSizeOfTheWindow(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	c := dialHub(t, hub)
	var wires [][]byte
	for i := 0; i < 5000; i++ {
		wire, err := client.Seal(nil, KindProbe, nil)
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, wire)
	}
	sent := 0
	for i := 0; i < len(wires); i += 2 {
		// Every other datagram is lost, and each pair arrives swapped.
		j := i
		if i%4 == 0 && i+2 < len(wires) {
			j = i + 2
		} else if i%4 == 2 {
			j = i - 2
		}
		if _, err := c.Write(wires[j]); err != nil {
			t.Fatal(err)
		}
		sent++
		if sent%64 == 0 {
			waitFor(t, hub, func(s Stats) bool { return s.Accepted == uint64(sent) })
		}
	}
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == uint64(sent) })
	if _, err := c.Write(wires[4998]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wires[100]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, hub, func(s Stats) bool { return s.ReplayDrops == 1 && s.TagDrops == 1 })
	hub.mu.Lock()
	registered.recvMu.Lock()
	inWindow := registered.recvTop - low(registered.recvHigh)
	live, index, spent := len(registered.recvTags), len(hub.index), len(hub.spent)
	registered.recvMu.Unlock()
	hub.mu.Unlock()
	if inWindow != window || index+spent != window || live != index {
		t.Fatalf("window %d, session tags %d, hub tags %d live and %d spent", inWindow, live, index, spent)
	}
	hub.Remove(registered)
	if len(hub.index) != 0 || len(hub.spent) != 0 {
		t.Fatalf("session tags left in hub: live=%d spent=%d", len(hub.index), len(hub.spent))
	}
}

func TestGameDatagramsHaveNoFixedPrefixOrLength(t *testing.T) {
	client, _ := pair(t)
	payload := bytes.Repeat([]byte{7}, 200)
	lengths := map[int]bool{}
	var first [8]byte
	var varied [8]bool
	for i := 0; i < 256; i++ {
		wire, err := client.Seal(nil, KindData, payload)
		if err != nil {
			t.Fatal(err)
		}
		lengths[len(wire)] = true
		if i == 0 {
			copy(first[:], wire[:8])
			continue
		}
		for j := range first {
			varied[j] = varied[j] || wire[j] != first[j]
		}
	}
	for j, ok := range varied {
		if !ok {
			t.Fatalf("tag byte %d stayed fixed across game packets", j)
		}
	}
	if len(lengths) < 16 {
		t.Fatalf("only %d wire lengths for one game payload", len(lengths))
	}
}

func FuzzOpenPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, MaxWire+1))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, receiver := pair(t)
		_, _ = receiver.Open(wire)
	})
}

func BenchmarkCodecRoundTrip(b *testing.B) {
	psk := bytes.Repeat([]byte{7}, 32)
	secret := bytes.Repeat([]byte{9}, 40)
	clientKeys, _ := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	serverKeys, _ := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	client, server := NewSession(clientKeys), NewSession(serverKeys)
	payload := bytes.Repeat([]byte{5}, 200)
	var wire [MaxWire]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet, err := client.Seal(wire[:0], KindData, payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := server.Open(packet); err != nil {
			b.Fatal(err)
		}
	}
}
