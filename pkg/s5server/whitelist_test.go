package s5server

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ALLOWED_IPS is the setting whose whole job is to keep everyone else out, so
// a list it cannot read must stop the server rather than become an empty list
// - and an empty list means no restriction.
//
// Finding F10 of docs/reports/code-quality-audit-2026-09-20.md.

func TestABadClientWhitelistIsRefusedBeforeTheServerExists(t *testing.T) {
	cases := []struct {
		name string
		ips  []string
		want string
	}{
		{"a typo in an address", []string{"192.0.2.OOPS"}, "192.0.2.OOPS"},
		{"one bad entry among good ones", []string{"127.0.0.1", "192.0.2.OOPS"}, "192.0.2.OOPS"},
		{"a network in CIDR", []string{"10.0.0.0/8"}, "network"},
		{"a host and port", []string{"127.0.0.1:1080"}, "127.0.0.1:1080"},
		{"a name instead of an address", []string{"localhost"}, "localhost"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ListenIP = "127.0.0.1"
			cfg.RequireAuth = false
			cfg.AllowedIPs = tc.ips

			_, err := NewServer(cfg)
			if err == nil {
				t.Fatal("NewServer accepted a whitelist it cannot enforce")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewServer failed with %q, which does not name %q", err, tc.want)
			}
			// The same list, the same verdict: the running server must not
			// disagree with the one that would not start.
			srv := serverWithWhitelist(t, nil)
			if err := srv.UpdateWhitelist(tc.ips); err == nil {
				t.Fatal("UpdateWhitelist accepted a list NewServer refused")
			}
		})
	}
}

// Punctuation is not an address: a trailing comma in the environment leaves
// the addresses beside it in force.
func TestAWhitelistIgnoresEmptyEntriesAndSpaces(t *testing.T) {
	list, err := parseWhitelist([]string{" 127.0.0.1 ", "", "  ", "::1"})
	if err != nil {
		t.Fatalf("parseWhitelist: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("parsed %d addresses, want 2", len(list))
	}
	if !list[0].Equal(net.ParseIP("127.0.0.1")) || !list[1].Equal(net.IPv6loopback) {
		t.Fatalf("parsed %v, want 127.0.0.1 and ::1", list)
	}

	// Nothing but punctuation is nothing at all, which is no restriction -
	// the same as an unset ALLOWED_IPS.
	empty, err := parseWhitelist([]string{"", " "})
	if err != nil {
		t.Fatalf("parseWhitelist on blanks: %v", err)
	}
	if empty != nil {
		t.Fatalf("blank entries became a whitelist of %v", empty)
	}
}

// serverWithWhitelist starts a plain SOCKS5 listener with the given list and
// returns the running server.
func serverWithWhitelist(t *testing.T, ips []string) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.Port = reservePort(t)
	cfg.RequireAuth = false
	cfg.AllowedIPs = ips
	srv := startServer(t, cfg)
	t.Cleanup(func() { _ = srv })
	return srv
}

// plainAddr is where the plain SOCKS5 listener of a test server sits.
func plainAddr(srv *Server) string {
	return net.JoinHostPort(srv.cfg.ListenIP, srv.cfg.Port)
}

// The list that does parse is enforced, so the test above is refusing
// something that would otherwise have had teeth.
func TestAWhitelistThatParsesKeepsOtherAddressesOut(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1: reserved for documentation, never a loopback
	// client, so the connection below is off the list by construction.
	srv := serverWithWhitelist(t, []string{"192.0.2.1"})

	conn, err := net.DialTimeout("tcp", plainAddr(srv), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		// A refused connection may already be gone; that is the point.
		return
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err == nil {
		t.Fatalf("an address off the whitelist got a SOCKS5 greeting %v", reply)
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("an address off the whitelist was neither served nor closed: %v", err)
		}
	}

	// And the list can still be widened at runtime.
	if err := srv.UpdateWhitelist([]string{"192.0.2.1", "127.0.0.1", "::1"}); err != nil {
		t.Fatalf("UpdateWhitelist: %v", err)
	}
	ok, err := net.DialTimeout("tcp", plainAddr(srv), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after widening: %v", err)
	}
	defer func() { _ = ok.Close() }()
	_ = ok.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := ok.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write after widening: %v", err)
	}
	if _, err := io.ReadFull(ok, reply[:]); err != nil {
		t.Fatalf("an address on the whitelist was refused: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("greeting reply %v, want 05 00", reply)
	}
}
