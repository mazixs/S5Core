package s5server

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// connectNoAuth runs the greeting and a CONNECT to a literal IPv4 target and
// returns the reply code of the server.
func connectNoAuth(t *testing.T, proxy, target string) byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	ap := netip.MustParseAddrPort(target)
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ap.Addr().AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, ap.Port())
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return reply[1]
}

// The server of a deployment sits on a machine with a loopback, a private
// network and often a metadata service, and a client of a proxy reaches all
// of them unless it is told it may not (Ч-27). The refusal is the setting of
// the server, and the same target is reachable without it.
func TestAPrivateDestinationIsRefusedOnlyWhenTheServerSaysSo(t *testing.T) {
	echo := startEchoServer(t)

	for _, tc := range []struct {
		name string
		deny bool
		want byte
	}{
		{"denied", true, 0x02},
		{"allowed", false, 0x00},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := reservedPort(t)
			startServer(t, Config{
				Port:            port,
				ListenIP:        "127.0.0.1",
				DenyPrivateDest: tc.deny,
			})
			if got := connectNoAuth(t, "127.0.0.1:"+port, echo); got != tc.want {
				t.Fatalf("CONNECT to the loopback answered 0x%02x, want 0x%02x", got, tc.want)
			}
		})
	}
}
