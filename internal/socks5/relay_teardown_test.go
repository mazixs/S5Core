package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// finAtCloseDest refuses every write and ends its read cleanly only when the
// relay closes it: the destination's FIN arriving at the very moment the
// other half failed and the relay tore both down. On a real socket that is a
// race; here it is the only possible order.
type finAtCloseDest struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (d *finAtCloseDest) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.EOF
}

func (d *finAtCloseDest) Write([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func (d *finAtCloseDest) CloseWrite() error { return nil }

func (d *finAtCloseDest) Close() error {
	d.once.Do(func() { close(d.closed) })
	return d.Conn.Close()
}

// A half that ends cleanly after the other one failed is not a half-close:
// the relay has already torn both sides down and the session is closed. It
// used to enter HalfClosed from Closed, which the table refuses; the field
// run caught one such refusal in an hour of idle connections cut by
// READ_TIMEOUT.
func TestACleanEndAfterTheTeardownIsNotAHalfClose(t *testing.T) {
	relayEnd, other := net.Pipe()
	target := &finAtCloseDest{Conn: relayEnd, closed: make(chan struct{})}
	t.Cleanup(func() { _ = other.Close() })
	conf := &Config{
		Dial: func(context.Context, string, string) (net.Conn, error) { return target, nil },
	}

	var illegal atomic.Int32
	var first atomic.Value
	obs := func(tr session.Transition) {
		if tr.Illegal && illegal.Add(1) == 1 {
			first.Store(tr.Region.String() + ": " + tr.FromName() + " -> " + tr.ToName())
		}
	}
	sess := session.NewRegistry(obs).Open("plain", false, session.SLA{Dial: time.Hour})
	client := serveWithSession(t, conf, sess)

	greet(t, client)
	req := []byte{5, ConnectCommand, 0, ipv4Address, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], 8080)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("connect failed with reply %#x", reply[1])
	}

	// One byte towards the destination fails the write, and the relay ends.
	go func() { _, _ = client.Write([]byte{1}) }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, client)

	waitForProtocol(t, sess, session.Closed)
	if n := illegal.Load(); n != 0 {
		t.Fatalf("%d illegal transitions, the first %v", n, first.Load())
	}
}
