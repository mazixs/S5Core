package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// drainDest is a destination that, once its write half is closed by the
// relay, sends one last chunk and then goes silent - the shape of a server
// answering the request that was in flight when the client's quota ran out.
type drainDest struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (d *drainDest) CloseWrite() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// A quota that runs out mid-transfer must not drop what the destination has
// already sent: the account region moves to Grace, the protocol region to
// HalfClosed, the destination gets to finish its answer within the grace
// window, and only then is the session closed. This is "the quota takes
// effect in-flight" from the Ф6-1 gate.
func TestAQuotaLetsInFlightDataDrainThenCutsTheSession(t *testing.T) {
	const limit = 100 * 1024
	const tail = "the-answer-that-was-in-flight"

	var counter atomic.Int64
	status := func(string) SessionStatus {
		if counter.Load() < limit {
			return SessionAllowed
		}
		return SessionQuotaExceeded
	}

	relayEnd, destEnd := net.Pipe()
	target := &drainDest{Conn: relayEnd, closed: make(chan struct{})}

	conf := &Config{
		AuthMethods: []Authenticator{UserPassAuthenticator{
			Credentials: StaticCredentials{"u": "p"},
		}},
		TrafficCounter: func(string) *atomic.Int64 { return &counter },
		SessionStatus:  status,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return target, nil
		},
	}

	var mu sync.Mutex
	var proto, acct []string
	obs := func(tr session.Transition) {
		if tr.Illegal {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch tr.Region {
		case session.RegionProtocol:
			proto = append(proto, tr.ToName())
		case session.RegionAccount:
			acct = append(acct, tr.ToName())
		}
	}
	sess := session.NewRegistry(obs).Open("plain", false, session.SLA{Grace: 300 * time.Millisecond})

	client := serveWithSession(t, conf, sess)

	// The destination streams until the relay closes the write half towards
	// it, then delivers the tail and stays quiet.
	go func() {
		block := make([]byte, 16*1024)
		for {
			select {
			case <-target.closed:
				_, _ = destEnd.Write([]byte(tail))
				return
			default:
				if _, err := destEnd.Write(block); err != nil {
					return
				}
			}
		}
	}()

	// Authenticate and CONNECT in one batch, then read the two replies and the
	// bound-address reply: 2 + 2 + 10 bytes before the relay starts.
	req := []byte{5, 1, UserPassAuth, userAuthVersion, byte(len("u"))}
	req = append(req, "u"...)
	req = append(req, byte(len("p")))
	req = append(req, "p"...)
	req = append(req, 5, ConnectCommand, 0, ipv4Address, 127, 0, 0, 1, 0, 0)
	binary.BigEndian.PutUint16(req[len(req)-2:], 8080)
	// net.Pipe has no buffer: the server writes its method-selection and auth
	// replies back to us while we are still sending, so the send has to run
	// alongside the read rather than finish before it, or both ends block on
	// a write the other is not yet reading.
	go func() { _, _ = client.Write(req) }()
	head := make([]byte, 14)
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	if head[3] != authSuccess || head[5] != successReply {
		t.Fatalf("handshake refused: % x", head)
	}

	// Read everything the relay delivers until it closes. The whole transfer
	// is a little over the quota plus the tail, so keeping all of it costs
	// nothing and lets the last bytes be checked exactly.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got bytes.Buffer
	if _, err := io.Copy(&got, client); err != nil && got.Len() == 0 {
		t.Fatalf("relay delivered nothing: %v", err)
	}

	if got.Len() < limit {
		t.Fatalf("only %d bytes reached the client, less than the %d quota", got.Len(), limit)
	}
	if !bytes.HasSuffix(got.Bytes(), []byte(tail)) {
		n := got.Len()
		from := n - len(tail) - 8
		if from < 0 {
			from = 0
		}
		t.Fatalf("the in-flight tail is not the last thing the client got; stream ends with %q", got.Bytes()[from:])
	}

	mu.Lock()
	gotProto, gotAcct := append([]string(nil), proto...), append([]string(nil), acct...)
	mu.Unlock()
	if !containsSeq(gotProto, "relay", "half_closed", "closed") {
		t.Fatalf("protocol region did not go relay->half_closed->closed: %v", gotProto)
	}
	if !containsSeq(gotAcct, "grace", "quota_exceeded") {
		t.Fatalf("account region did not go grace->quota_exceeded: %v", gotAcct)
	}
}

// containsSeq reports whether want appears as an ordered (not necessarily
// contiguous) subsequence of got.
func containsSeq(got []string, want ...string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && g == want[i] {
			i++
		}
	}
	return i == len(want)
}
