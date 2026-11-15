package main

import (
	"io"
	"net"
	"testing"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// A kernel without tcpi_bytes_acked reports a zero on every read, so the
// count never moves. A setup that failed on such a spare is not repeated:
// the server may have the request. Where the count is known and did not
// move, it is repeated, before and after the spare is closed.
func TestASpareWithoutAnAcknowledgedCountIsNotRepeated(t *testing.T) {
	t.Cleanup(func() { tcpInfoOf = tcptune.InfoOf })
	for _, known := range []bool{false, true} {
		tcpInfoOf = func(net.Conn) (tcptune.Info, bool) {
			return tcptune.Info{State: tcptune.StateEstablished, BytesAckedKnown: known}, true
		}
		a, b := net.Pipe()
		t.Cleanup(func() { _ = b.Close() })
		spare := newTakenSpare(a)
		for _, closed := range []bool{false, true} {
			if closed {
				_ = spare.Close()
			}
			err := tunnelFail(phaseGreeting, "failed to send greeting: %w", io.ErrClosedPipe)
			markSpareFailure(err, endedUnanswered(err), spare)
			if mayRetry(err) != known {
				t.Fatalf("count known %v, spare closed %v: repeated %v", known, closed, mayRetry(err))
			}
			if countsAgainstThePath(err) {
				t.Fatalf("count known %v, spare closed %v: a failure on a spare counted against the path", known, closed)
			}
		}
	}
}
