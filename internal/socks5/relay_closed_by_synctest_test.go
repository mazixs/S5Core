package socks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"

	"github.com/mazixs/S5Core/internal/session"
)

// answersFIN is one end of a relay that answers the server's half-close by
// ending its own stream, the way an echo server closes on EOF. Its CloseWrite
// returns only once what the answer set off has run through the relay: the
// order a loaded scheduler can produce, where the answer is reported before
// the half-close that caused it.
type answersFIN struct {
	net.Conn
	answer func()
}

func (c *answersFIN) CloseWrite() error {
	c.answer()
	synctest.Wait()
	return nil
}

// The side that ended its stream first ended the relay, even when the other
// side, answering the half-close, gets its end reported first.
func TestTheSideThatEndsFirstEndsTheRelay(t *testing.T) {
	for _, tc := range []struct {
		name        string
		clientFirst bool
		want        string
	}{
		{"client FIN, target answers", true, ClosedByClient},
		{"target FIN, client answers", false, ClosedByTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientSide, serverSide := net.Pipe()
				defer clientSide.Close()
				defer serverSide.Close()
				targetSide, peer := net.Pipe()
				defer targetSide.Close()

				var client conn = serverSide
				target := targetSide
				var fromClient io.Reader
				if tc.clientFirst {
					fromClient = bytes.NewReader(nil)
					target = &answersFIN{Conn: targetSide, answer: func() { _ = peer.Close() }}
				} else {
					upstream, closeUpstream := io.Pipe()
					fromClient = upstream
					client = &answersFIN{Conn: serverSide, answer: func() { _ = closeUpstream.Close() }}
					_ = peer.Close()
				}

				server, err := New(&Config{})
				if err != nil {
					t.Fatal(err)
				}
				end := &ConnEnd{}
				if err := server.relayConnect(context.Background(), client, &Request{
					bufConn: fromClient, session: auditRelaySession(session.SLA{}), end: end,
				}, target); err != nil {
					t.Fatal(err)
				}
				if end.ClosedBy != tc.want {
					t.Errorf("closed by %q, want %q", end.ClosedBy, tc.want)
				}
			})
		})
	}
}
