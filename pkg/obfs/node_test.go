package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-4, end to end: the acceptance criterion is stated as "a frame
// accepted by node A is refused by node B", and that is a property of whole
// connections, not of the derivation alone.

// tunnelBetween opens a connection between a client configured for one node
// and a server that answers to a set of them, and reports whether a byte
// gets through.
func tunnelBetween(t *testing.T, clientNode string, serverNodes []string) bool {
	t.Helper()

	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	now := func() time.Time { return base }
	psk := bytes.Repeat([]byte("k"), 32)

	accepts := make([]veil.Context, 0, len(serverNodes))
	for _, id := range serverNodes {
		accepts = append(accepts, veil.Context{NodeID: id})
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client, err := NewClientConn(clientConn, Config{
		PSK:    psk,
		Scheme: &veil.Clocked{Context: veil.Context{NodeID: clientNode}, Now: now},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverConn, Config{
		PSK:    psk,
		Scheme: &veil.Clocked{Context: accepts[0], Accepts: accepts, Now: now},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	msg := []byte("a recording made against one node is worthless against another")
	go func() {
		_, _ = client.Write(msg)
	}()

	_ = server.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 128)
	n, err := server.Read(buf)
	return err == nil && bytes.Equal(buf[:n], msg)
}

func TestATunnelDoesNotCrossNodes(t *testing.T) {
	if !tunnelBetween(t, "edge", []string{"edge"}) {
		t.Fatal("a node refused its own client")
	}
	if tunnelBetween(t, "edge", []string{"core"}) {
		t.Error("a client configured for one node opened a tunnel to another")
	}
}

func TestANodeBeingMigratedAnswersToBothNames(t *testing.T) {
	both := []string{"core", "edge"}
	if !tunnelBetween(t, "core", both) {
		t.Error("a migrating node refused a client on its new name")
	}
	if !tunnelBetween(t, "edge", both) {
		t.Error("a migrating node refused a client on its old name")
	}
	if tunnelBetween(t, "berlin", both) {
		t.Error("a migrating node accepted a name it was never given")
	}
}
