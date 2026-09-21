package socks5

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
)

// The handlers take the narrow conn interface - a place to write the reply and
// the address it came from - while the two UDP paths need the client's socket
// as well: an association keeps that connection as its lifetime marker and
// takes its local address and its deadlines. That requirement used to be three
// unchecked type assertions, so a caller holding anything else got a panic in
// the middle of an association instead of an error at its start. Found by
// golangci-lint (forcetypeassert) and confirmed by the tests below, which pass
// exactly such a caller.

// notASocket satisfies conn and nothing more, which is all the interface
// promises.
type notASocket struct {
	bytes.Buffer
}

func (n *notASocket) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51000}
}

// refusalOf runs one UDP handler against a caller that is not a socket and
// returns the error it produced, failing the test if it panicked instead.
func refusalOf(t *testing.T, name string, run func(conn) error, c conn) error {
	t.Helper()
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s panicked on a caller that is not a socket instead of refusing it: %v", name, r)
			}
		}()
		err = run(c)
	}()
	return err
}

func TestAUDPAssociationRefusesACallerThatIsNotASocket(t *testing.T) {
	srv := &Server{config: &Config{}}

	handlers := map[string]func(conn) error{
		"associate 0x03": func(c conn) error {
			return srv.handleAssociate(context.Background(), c, &Request{})
		},
		"tcpmux 0x83": func(c conn) error {
			return srv.handleUDPTcpmux(context.Background(), c, &Request{})
		},
	}

	for name, run := range handlers {
		t.Run(name, func(t *testing.T) {
			caller := &notASocket{}
			err := refusalOf(t, name, run, caller)
			if err == nil {
				t.Fatalf("%s accepted a caller that cannot hold the association open", name)
			}
			if !strings.Contains(err.Error(), "socket") {
				t.Fatalf("the error does not say what was missing: %v", err)
			}

			// The client is told, rather than left waiting for a reply that
			// never comes: the handler owns the answer to this request.
			reply := caller.Bytes()
			if len(reply) < 2 {
				t.Fatalf("%s refused the request without answering it: % x", name, reply)
			}
			if reply[0] != Socks5Version {
				t.Fatalf("the reply does not start with the SOCKS5 version: % x", reply)
			}
			if reply[1] != serverFailure {
				t.Fatalf("the client was told 0x%02x, want a server failure 0x%02x", reply[1], serverFailure)
			}
		})
	}
}
