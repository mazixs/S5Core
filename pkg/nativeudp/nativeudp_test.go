package nativeudp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

func pair(t *testing.T) (*Session, *Session) {
	t.Helper()
	psk := bytes.Repeat([]byte{7}, 32)
	secret := bytes.Repeat([]byte{9}, 40)
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

func TestHubProbeAndData(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0")
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

func TestAuthenticatedPacketMovesPeer(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	var firstPort uint16
	for i := 0; i < 2; i++ {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := client.Seal(nil, KindProbe, nil)
		if i == 1 {
			forged := append([]byte(nil), wire...)
			forged[len(forged)-1] ^= 1
			if _, err := c.Write(forged); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for hub.Stats().AuthDrops == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if peer, ok := registered.Peer(); !ok || peer.Port() != firstPort {
				t.Fatalf("forged packet moved peer to %v", peer)
			}
		}
		_, _ = c.Write(wire)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [MaxWire]byte
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Open(b[:n]); err != nil {
			t.Fatal(err)
		}
		peer, ok := registered.Peer()
		if !ok || peer.Port() != uint16(c.LocalAddr().(*net.UDPAddr).Port) {
			t.Fatalf("peer after migration: %v", peer)
		}
		if i == 0 {
			firstPort = peer.Port()
		}
		_ = c.Close()
	}
}

func TestHubStatsClassifyDropsAndBoundSessions(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0")
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
