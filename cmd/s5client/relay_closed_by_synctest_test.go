package main

import (
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// answersFIN is one end of a relay that answers the half-close passed on to it
// by ending its own stream, the way an echo server closes on EOF. Its CloseWrite
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

// The side that ended its stream first ended the tunnel, even when the other
// side, answering the half-close, gets its end reported first.
func TestTheSideThatEndsFirstEndsTheTunnel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		appFirst bool
		want     string
	}{
		{"application FIN, tunnel answers", true, closedByApp},
		{"tunnel FIN, application answers", false, closedByServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				app, appRelay := net.Pipe()
				defer app.Close()
				tunnelRelay, server := net.Pipe()
				defer server.Close()

				client, tunnel := appRelay, tunnelRelay
				if tc.appFirst {
					tunnel = &answersFIN{Conn: tunnelRelay, answer: func() { _ = server.Close() }}
					_ = app.Close()
				} else {
					client = &answersFIN{Conn: appRelay, answer: func() { _ = app.Close() }}
					_ = server.Close()
				}

				r := relayAfter(client, tunnel, nil)
				logRelayEnd("test", "example.com", testClientParams(), 0, time.Now(), r)
				if want := "closed_by=" + tc.want; !strings.Contains(logs.String(), want) {
					t.Errorf("the log does not say %s:\n%s", want, logs.String())
				}
			})
		})
	}
}
