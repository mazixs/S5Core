package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/userstore"
)

// maxShutdown is how long SIGTERM to "everything has stopped" may take.
const maxShutdown = 3 * time.Second

// answerWithin is the deadline for a login that runs Argon2id: over 3 s under
// race and coverage with every other package competing for the CPU.
const answerWithin = 15 * time.Second

// oneUserFile writes a users.json with a single account and no traffic used.
func oneUserFile(t *testing.T) string {
	t.Helper()
	users := userstore.UsersFile{
		Users: []userstore.UserAccount{{
			ID:       "u-001",
			Username: "alice",
			Password: "secret1",
			Enabled:  true,
		}},
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

func trafficUsed(t *testing.T, path, username string) int64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	var file userstore.UsersFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse users file: %v", err)
	}
	for _, u := range file.Users {
		if u.Username == username {
			return u.TrafficUsedBytes
		}
	}
	t.Fatalf("user %q is not in the file", username)
	return 0
}

// waitForProxy dials the proxy until it answers, so the test does not race
// the listener coming up.
func waitForProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the proxy never accepted a connection on %s", addr)
	return nil
}

// serverPackages are the frames that identify a goroutine as belonging to the
// proxy rather than to the test or the runtime. Counting these instead of
// comparing runtime.NumGoroutine to a baseline matters: the baseline moves on
// its own - signal.NotifyContext, for one, retires its own goroutine when the
// signal arrives - and a moving baseline hides exactly one leaked goroutine.
var serverPackages = []string{
	"S5Core/internal/socks5.",
	"S5Core/pkg/s5server.",
}

// countServerGoroutines counts the goroutines currently inside the proxy.
func countServerGoroutines() int {
	var n int
	for _, g := range strings.Split(goroutineDump(), "\n\n") {
		for _, pkg := range serverPackages {
			if strings.Contains(g, pkg) {
				n++
				break
			}
		}
	}
	return n
}

// waitForNoServerGoroutines gives the runtime a moment to finish what the
// shutdown started, then reports how many proxy goroutines are still running.
func waitForNoServerGoroutines() int {
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.Gosched()
		left := countServerGoroutines()
		if left == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func goroutineDump() string {
	buf := make([]byte, 1<<16)
	return string(buf[:runtime.Stack(buf, true)])
}

// socks5ConnectAuth performs a username/password handshake and a CONNECT.
func socks5ConnectAuth(conn net.Conn, user, pass, addr string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x02 {
		return errUnexpected("the server did not select username/password auth")
	}

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errUnexpected("authentication was refused")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 10) // IPv4 reply: the destination is an address here
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return errUnexpected("connect was refused")
	}
	return nil
}

type errUnexpected string

func (e errUnexpected) Error() string { return string(e) }
