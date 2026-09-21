package socks5

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// FRAG says a datagram is a piece of a larger one. Nothing here puts the
// pieces back together, so forwarding a piece means handing a target part of a
// message as though it were all of it - RFC 1928, section 7, says to drop it
// instead (audit finding F18).

// withFrag builds a SOCKS5 UDP request and sets its FRAG byte.
func withFrag(frag byte, dest *AddrSpec, payload string) []byte {
	datagram := BuildUDPHeader(dest, []byte(payload))
	datagram[2] = frag
	return datagram
}

func TestTheParserRefusesAFragment(t *testing.T) {
	dest := &AddrSpec{IP: net.ParseIP("198.51.100.7"), Port: 53}

	for _, tc := range []struct {
		name string
		frag byte
	}{
		{"the first piece", 0x01},
		{"a later piece", 0x7f},
		{"the last piece, standby bit set", 0x80},
		{"a piece whose number is nonsense", 0xff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseUDPHeader(withFrag(tc.frag, dest, "half a question"))
			if err == nil {
				t.Fatalf("FRAG %#x was parsed as a whole datagram", tc.frag)
			}
			if !errors.Is(err, errFragmentedDatagram) {
				t.Fatalf("FRAG %#x was refused for the wrong reason: %v", tc.frag, err)
			}
		})
	}

	// And the unfragmented case still parses, so the check above is about
	// FRAG and not about the header around it.
	hdrLen, got, err := ParseUDPHeader(withFrag(0x00, dest, "a whole question"))
	if err != nil {
		t.Fatalf("an unfragmented datagram was refused: %v", err)
	}
	if got.Address() != dest.Address() {
		t.Fatalf("the parser read the destination as %s, want %s", got.Address(), dest.Address())
	}
	if hdrLen != 10 {
		t.Fatalf("header length %d, want 10 for an IPv4 destination", hdrLen)
	}
}

// The parser is where the decision is made, but the decision is only worth
// anything if it is on the path every datagram takes. Both UDP modes are
// checked, because they are two loops with two copies of the same steps.
//
// The assertion is made at the destination and by order: the client sends a
// fragment and then a whole datagram, and the first thing to arrive must be
// the whole one. That says both halves of what the fix claims - the fragment
// was dropped, and dropping it did not end the association.
func TestAFragmentNeverReachesItsDestination(t *testing.T) {
	t.Run("associate", func(t *testing.T) {
		sink := newUDPSink(t, false)
		rules := &recordingRules{allowed: map[string]bool{sink.spec().Address(): true}}
		addr := udpRuleServer(t, rules, &countingResolver{})

		dest := sink.addr()
		setup := []byte{0x01, 127, 0, 0, 1, byte(dest.Port >> 8), byte(dest.Port)}
		conn, reply := associateThrough(t, addr, AssociateCommand, setup)
		defer func() { _ = conn.Close() }()

		proxyUDP := &net.UDPAddr{
			IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
			Port: int(reply[8])<<8 | int(reply[9]),
		}
		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("client socket: %v", err)
		}
		defer func() { _ = client.Close() }()

		if _, err := client.WriteToUDP(withFrag(0x01, sink.spec(), fragmentPayload), proxyUDP); err != nil {
			t.Fatalf("sending the fragment: %v", err)
		}
		if _, err := client.WriteToUDP(withFrag(0x00, sink.spec(), wholePayload), proxyUDP); err != nil {
			t.Fatalf("sending the whole datagram: %v", err)
		}

		assertFirstDatagramIsWhole(t, sink)
	})

	t.Run("tunnelled", func(t *testing.T) {
		sink := newUDPSink(t, false)
		rules := &recordingRules{allowed: map[string]bool{sink.spec().Address(): true}}
		addr := udpRuleServer(t, rules, &countingResolver{})

		dest := sink.addr()
		setup := []byte{0x01, 127, 0, 0, 1, byte(dest.Port >> 8), byte(dest.Port)}
		conn, _ := associateThrough(t, addr, UDPTunnelCommand, setup)
		defer func() { _ = conn.Close() }()

		send := func(frag byte, payload string) {
			t.Helper()
			body := withFrag(frag, sink.spec(), payload)
			frame := make([]byte, 2+len(body))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
			copy(frame[2:], body)
			if _, err := conn.Write(frame); err != nil {
				t.Fatalf("write frame: %v", err)
			}
		}

		send(0x01, fragmentPayload)
		send(0x00, wholePayload)

		assertFirstDatagramIsWhole(t, sink)
	})
}

const (
	fragmentPayload = "half a question"
	wholePayload    = "a whole question"
)

// assertFirstDatagramIsWhole reads one datagram at the destination and insists
// it is the unfragmented one.
func assertFirstDatagramIsWhole(t *testing.T, sink *udpSink) {
	t.Helper()
	_ = sink.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sink.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("nothing reached the destination, so the association did not survive the fragment: %v", err)
	}
	switch got := string(buf[:n]); got {
	case wholePayload:
	case fragmentPayload:
		t.Fatal("a fragment was forwarded to its destination as a whole datagram")
	default:
		t.Fatalf("the destination got %q, want %q", got, wholePayload)
	}
}
