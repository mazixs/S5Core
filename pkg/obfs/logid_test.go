package obfs

import (
	"net"
	"regexp"
	"testing"
)

// Both ends name the connection the same way, from the session they share,
// and nothing on the wire carries the name.
func TestBothEndsGiveAConnectionTheSameLogID(t *testing.T) {
	client, server, _, _ := controlPair(t,
		Config{Hello: &Hello{Version: "v2.3.0-rc6"}},
		Config{},
	)
	if id := LogIDOf(server); id != "" {
		t.Fatalf("the server named the connection %q before reading the opening", id)
	}
	payload := []byte("ping")
	go func() { _, _ = client.Write(payload) }()
	relayOnce(t, server, payload)

	id := LogIDOf(netConnWrapper{unwrapWrapper{server}})
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(id) {
		t.Fatalf("server log id %q", id)
	}
	if got := LogIDOf(client); got != id {
		t.Fatalf("client %q, server %q", got, id)
	}
	if got := ClientBuildOf(netConnWrapper{server}); got != "v2.3.0-rc6" {
		t.Errorf("client build %q", got)
	}

	other, otherServer, _, _ := controlPair(t, Config{}, Config{})
	go func() { _, _ = other.Write(payload) }()
	relayOnce(t, otherServer, payload)
	if LogIDOf(other) == id {
		t.Error("two connections got one log id")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if LogIDOf(a) != "" || ClientBuildOf(a) != "" {
		t.Error("a connection without obfs got a log id")
	}
}
