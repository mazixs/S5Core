package s5server

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
	"github.com/mazixs/S5Core/internal/userstore"
)

// reservedPort picks a port nothing is listening on. freePort lives behind
// the loadtest build tag, and duplicating four lines is cheaper than moving it.
func reservedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split port: %v", err)
	}
	_ = l.Close()
	return port
}

// trafficInFile reads the byte count the users file holds for one account.
func trafficInFile(t *testing.T, path, username string) int64 {
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

// Stop used to save the users file before it closed the connections, and a
// relay half hands its last batch to the counter only when it ends. Anything
// a live session had moved since its last batch - up to relay.FlushThreshold
// per direction - was therefore written to disk as if it had never happened,
// on every restart and without a word in the log.
//
// The session here is still live when Stop is called, and it has moved less
// than one batch, so every byte of it is in the batch that only the shutdown
// can deliver. The flush interval is an hour: nothing but Stop can write the
// file.
func TestStopPersistsWhatALiveSessionMoved(t *testing.T) {
	echoAddr := startEchoServer(t)
	usersPath := testUsersFile(t)

	srv := startServer(t, Config{
		Port:                 reservedPort(t),
		ListenIP:             "127.0.0.1",
		RequireAuth:          true,
		UsersFile:            usersPath,
		TrafficFlushInterval: time.Hour,
	})

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+srv.cfg.Port, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks5Connect(conn, "alice", "secret1", echoAddr); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	payload := strings.Repeat("x", 4096)
	if len(payload) >= relay.FlushThreshold {
		t.Fatalf("the payload is %d bytes, which is a whole batch: the test would pass without the fix", len(payload))
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len(payload))); err != nil {
		t.Fatalf("read: %v", err)
	}

	if used := trafficInFile(t, usersPath, "alice"); used != 0 {
		t.Fatalf("the file already holds %d bytes; then it is not Stop that wrote them", used)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if used := trafficInFile(t, usersPath, "alice"); used < int64(len(payload)) {
		t.Errorf("the file holds %d bytes, want at least %d: the last batch of a live session was dropped", used, len(payload))
	}
}
