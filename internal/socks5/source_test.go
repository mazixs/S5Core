package socks5

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// recordingStore is a credential store that wants to know where the attempt
// came from - the shape rate limiting needs.
type recordingStore struct {
	mu      sync.Mutex
	sources []string
}

func (s *recordingStore) Valid(user, password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, "")
	return false
}

func (s *recordingStore) ValidFrom(user, password, source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, source)
	return password == "right"
}

func (s *recordingStore) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sources...)
}

// Rate limiting is only as good as what it is keyed on, so the address has to
// survive the trip from the listener to the credential store. Without this
// test the plumbing could quietly pass "" and every limit would share one
// bucket again.
func TestTheClientAddressReachesTheCredentialStore(t *testing.T) {
	store := &recordingStore{}
	server, err := New(&Config{
		AuthMethods: []Authenticator{UserPassAuthenticator{Credentials: store}},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = server.ServeContext(context.Background(), ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{5, 1, UserPassAuth}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if _, err := conn.Write([]byte{1, 3, 'b', 'o', 'b', 5, 'r', 'i', 'g', 'h', 't'}); err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if reply[1] != authSuccess {
		t.Fatalf("authentication failed with %#x", reply[1])
	}

	seen := store.seen()
	if len(seen) != 1 {
		t.Fatalf("store was asked %d times, want once", len(seen))
	}
	if seen[0] != "127.0.0.1" {
		t.Fatalf("store was told the source is %q, want the client address without the port", seen[0])
	}
}
