package nativeudp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// benchHub is one session through a hub on loopback, set up without the
// helpers of the other test files so that it builds against an older hub
// too (go test -overlay).
func benchHub(b *testing.B) (*Hub, *Session, *Session, *net.UDPConn) {
	b.Helper()
	psk := bytes.Repeat([]byte{7}, 32)
	secret := bytes.Repeat([]byte{9}, 40)
	clientKeys, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		b.Fatal(err)
	}
	serverKeys, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	if err != nil {
		b.Fatal(err)
	}
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = hub.Close() })
	registered := hub.Register(serverKeys)
	b.Cleanup(func() { hub.Remove(registered) })
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(time.Minute))
	return hub, NewSession(clientKeys), registered, c
}

// One application datagram each way through the hub: the reader's path to the
// association and the association's answer.
func BenchmarkHubRoundTrip(b *testing.B) {
	hub, client, registered, c := benchHub(b)
	payload := bytes.Repeat([]byte{5}, 200)
	write := func(wire []byte) error { _, err := c.Write(wire); return err }
	var buf [MaxWire]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.SealWrite(KindData, payload, write); err != nil {
			b.Fatal(err)
		}
		p := <-registered.Packets()
		p.Release()
		if err := hub.Send(registered, KindData, payload); err != nil {
			b.Fatal(err)
		}
		n, err := c.Read(buf[:])
		if err != nil {
			b.Fatal(err)
		}
		if _, err := client.Open(buf[:n]); err != nil {
			b.Fatal(err)
		}
	}
}

// A probe and its answer, which the hub writes itself.
func BenchmarkHubProbe(b *testing.B) {
	_, client, _, c := benchHub(b)
	write := func(wire []byte) error { _, err := c.Write(wire); return err }
	var buf [MaxWire]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.SealWrite(KindProbe, nil, write); err != nil {
			b.Fatal(err)
		}
		n, err := c.Read(buf[:])
		if err != nil {
			b.Fatal(err)
		}
		if p, err := client.Open(buf[:n]); err != nil || p.Kind != KindProbeAck {
			b.Fatal(err, p.Kind)
		}
	}
}
