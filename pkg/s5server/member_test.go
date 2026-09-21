package s5server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-5 moves user identification into the tunnel: the server
// resolves the account from the prologue, in time that does not depend on
// how many accounts there are, and the SOCKS5 handshake stops carrying a
// password. These tests are that property end to end - a real listener, a
// real tunnel, a real user file.

func memberUsersFile(t *testing.T, key []byte) string {
	t.Helper()
	users := userstore.UsersFile{
		Users: []userstore.UserAccount{
			{
				ID:        "u-001",
				Username:  "alice",
				Password:  "the password nobody should need",
				TunnelKey: base64.StdEncoding.EncodeToString(key),
				Enabled:   true,
			},
			{
				ID:       "u-002",
				Username: "bob",
				Password: "secret2",
				Enabled:  true,
			},
		},
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// reservePort hands back a port nothing is listening on. The listener is
// closed before the server binds it, which is the usual small race, and the
// usual answer: the window is microseconds and the port is not reused.
func reservePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func randomMemberKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, veil.MemberKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// connectAsMember runs the handshake a member's client runs: it offers
// no-auth alongside user/pass and sends no credentials, because the tunnel
// has already said who it is. It fails if the server asks for a password.
func connectAsMember(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := net.LookupPort("tcp", portStr)

	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	if greeting[1] != 0x00 {
		return fmt.Errorf("the server chose method 0x%02x, want no-auth: a member was asked for a password", greeting[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("connect refused: 0x%02x", reply[1])
	}
	// Bound address: one byte of length for a name, four for IPv4.
	switch reply[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		var n [1]byte
		if _, err = io.ReadFull(conn, n[:]); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(n[0])+2))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	}
	return err
}

// memberStand starts a server with one member and returns its obfuscated
// port, the member's key and the echo server to aim at.
func memberStand(t *testing.T, requireKey bool) (*Server, string, []byte, string) {
	t.Helper()
	key := randomMemberKey(t)
	echo := startEchoServer(t)
	cfg := Config{
		ListenIP:             "127.0.0.1",
		Port:                 reservePort(t),
		ObfsEnabled:          true,
		ObfsPort:             reservePort(t),
		ObfsPSK:              testPSK,
		ObfsMaxPadding:       256,
		ObfsMTU:              1400,
		RequireAuth:          true,
		UsersFile:            memberUsersFile(t, key),
		ObfsRequireMemberKey: requireKey,
	}
	srv := startServer(t, cfg)
	return srv, cfg.ObfsPort, key, echo
}

func dialMember(t *testing.T, port string, scheme veil.Scheme) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	tunnel, err := obfs.NewClientConn(raw, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 256,
		MTU:        1400,
		Scheme:     scheme,
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	return tunnel
}

func TestAMemberConnectsWithoutAPassword(t *testing.T) {
	srv, port, key, echo := memberStand(t, false)

	tunnel := dialMember(t, port, &veil.Roster{
		Member: veil.Member{ID: "alice", Key: key},
	})
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("a member could not connect: %v", err)
	}

	if _, err := tunnel.Write([]byte("member-ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len("member-ping"))
	if _, err := io.ReadFull(tunnel, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "member-ping" {
		t.Fatalf("echo returned %q", buf)
	}

	// The traffic has to land on the account the tunnel named, not on
	// nobody: that is what makes the identity worth resolving. The relay
	// batches the counter and flushes it when the session ends, so the
	// connection is closed first and the counter given a moment to land.
	_ = tunnel.Close()
	alice := srv.userStore.TrafficCounterFor("alice")
	deadline := time.Now().Add(2 * time.Second)
	for alice.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if used := alice.Load(); used == 0 {
		t.Error("no traffic was accounted to the member")
	}
	if used := srv.userStore.TrafficCounterFor("bob").Load(); used != 0 {
		t.Errorf("%d bytes were accounted to the wrong user", used)
	}
}

// A key that belongs to nobody must fail the way a wrong PSK fails: the
// server takes the connection, says nothing, and closes it.
func TestAStrangersKeyIsRefusedLikeAWrongPSK(t *testing.T) {
	_, port, _, echo := memberStand(t, false)

	tunnel := dialMember(t, port, &veil.Roster{
		Member: veil.Member{ID: "mallory", Key: randomMemberKey(t)},
	})
	_ = tunnel.SetDeadline(time.Now().Add(2 * time.Second))
	if err := connectAsMember(tunnel, echo); err == nil {
		t.Fatal("a key that belongs to no account was accepted")
	}
}

// Until the operator says otherwise, clients that have no key of their own
// keep working with a password. That is the migration window.
func TestTheSharedAccountStillWorksBesideMembers(t *testing.T) {
	_, port, _, echo := memberStand(t, false)

	tunnel := dialMember(t, port, veil.NewClocked())
	if err := socks5Connect(tunnel, "bob", "secret2", echo); err != nil {
		t.Fatalf("a client of the shared account was refused: %v", err)
	}
}

// And when the operator does say otherwise, the shared account is gone: a
// stolen PSK alone no longer reaches the server.
func TestRequiringMemberKeysClosesTheSharedAccount(t *testing.T) {
	_, port, key, echo := memberStand(t, true)

	t.Run("shared account", func(t *testing.T) {
		tunnel := dialMember(t, port, veil.NewClocked())
		_ = tunnel.SetDeadline(time.Now().Add(2 * time.Second))
		if err := socks5Connect(tunnel, "bob", "secret2", echo); err == nil {
			t.Fatal("a client with no member key connected to a server that requires one")
		}
	})

	t.Run("member", func(t *testing.T) {
		tunnel := dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
		if err := connectAsMember(tunnel, echo); err != nil {
			t.Fatalf("a member was refused: %v", err)
		}
	})
}

// Revoking an account has to reach the tunnel, not only the password check.
func TestReloadingUsersRevokesAMembersKey(t *testing.T) {
	srv, port, key, echo := memberStand(t, false)

	tunnel := dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("a member could not connect before revocation: %v", err)
	}

	// Alice is disabled and the file is reloaded the way SIGHUP reloads it.
	users := userstore.UsersFile{Users: []userstore.UserAccount{
		{ID: "u-001", Username: "alice", TunnelKey: base64.StdEncoding.EncodeToString(key), Enabled: false},
		{ID: "u-002", Username: "bob", Password: "secret2", Enabled: true},
	}}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv.cfg.UsersFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadUsers(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	after := dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
	_ = after.SetDeadline(time.Now().Add(2 * time.Second))
	if err := connectAsMember(after, echo); err == nil {
		t.Fatal("a revoked member still connects with their tunnel key")
	}
}
