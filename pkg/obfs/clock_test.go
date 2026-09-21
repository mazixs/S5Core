package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-3, end to end. pkg/veil proves the epoch arithmetic; what is
// proved here is that a whole connection lives or dies by it, and that a
// server refuses a skewed clock the same way it refuses a wrong key - after
// the first frame, with nothing on the wire to tell the two apart.

// tunnelAt opens a connection whose ends stand at different wall clocks and
// reports whether a byte written by the client reaches the server.
func tunnelAt(t *testing.T, clientSkew time.Duration, onSkew func(int64)) bool {
	t.Helper()

	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	psk := bytes.Repeat([]byte("k"), 32)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client, err := NewClientConn(clientConn, Config{
		PSK:    psk,
		Scheme: &veil.Clocked{Now: func() time.Time { return base.Add(clientSkew) }},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverConn, Config{
		PSK: psk,
		Scheme: &veil.Clocked{
			Now:         func() time.Time { return base },
			OnClockSkew: onSkew,
		},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	msg := []byte("the hour is inside the key, not on the wire")
	go func() {
		_, _ = client.Write(msg)
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := server.Read(buf)
	return err == nil && bytes.Equal(buf[:n], msg)
}

func TestATunnelSurvivesHoursOfClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{0, 45 * time.Minute, -45 * time.Minute, 2 * time.Hour, -2 * time.Hour} {
		if !tunnelAt(t, skew, nil) {
			t.Errorf("a client %v out of step could not open a tunnel", skew)
		}
	}
}

func TestATunnelDiesOnADayOfClockSkew(t *testing.T) {
	reported := make(chan int64, 1)
	if tunnelAt(t, 25*time.Hour, func(epochs int64) { reported <- epochs }) {
		t.Fatal("a client a day out of step opened a tunnel")
	}
	select {
	case epochs := <-reported:
		if epochs != 25 {
			t.Errorf("the server reported %d hours of skew, want 25", epochs)
		}
	default:
		t.Error("the server refused the connection without saying why; an operator sees a silent failure")
	}
}

// The refusal must be indistinguishable from the one a wrong PSK gets. A
// server that refused at the prologue would answer a stale replay faster
// than it answers a wrong payload, and that difference is measurable from
// outside.
//
// What a server actually does with a key it cannot use is unmask a length
// that is now a random 16-bit number and wait for bytes that never come. So
// the check is not "the reason is decrypt_fail" - it is that the reasons a
// skewed clock produces are the reasons a wrong PSK produces, and nothing
// else.
func TestAClockSkewIsRefusedLikeAWrongKey(t *testing.T) {
	const rounds = 8
	skewed := refusalReasons(t, rounds, func(base time.Time) (Config, Config) {
		psk := bytes.Repeat([]byte("k"), 32)
		return Config{PSK: psk, Scheme: &veil.Clocked{Now: func() time.Time { return base.Add(25 * time.Hour) }}},
			Config{PSK: psk, Scheme: &veil.Clocked{Now: func() time.Time { return base }}}
	})
	wrongKey := refusalReasons(t, rounds, func(base time.Time) (Config, Config) {
		clock := &veil.Clocked{Now: func() time.Time { return base }}
		return Config{PSK: bytes.Repeat([]byte("k"), 32), Scheme: clock},
			Config{PSK: bytes.Repeat([]byte("j"), 32), Scheme: clock}
	})

	for reason := range skewed {
		if !wrongKey[reason] {
			t.Errorf("a skewed clock is refused with reason %q, which a wrong PSK never produces - that is a distinguisher", reason)
		}
	}
	if len(skewed) == 0 {
		t.Error("a skewed clock was not refused at all")
	}
}

// refusalReasons opens `rounds` connections and collects the reasons the
// server gave. The read deadline is short on purpose: the interesting case
// is the server waiting for bytes that will never arrive, and the test has
// no reason to wait as long as a real one would.
func refusalReasons(t *testing.T, rounds int, configs func(base time.Time) (client, server Config)) map[FailureReason]bool {
	t.Helper()
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	seen := make(map[FailureReason]bool)

	for range rounds {
		clientCfg, serverCfg := configs(base)
		reasons := make(chan FailureReason, 4)
		serverCfg.OnFailure = func(fe *FrameError) { reasons <- fe.Reason }

		clientConn, serverConn := net.Pipe()
		client, err := NewClientConn(clientConn, clientCfg)
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		server, err := NewServerConn(serverConn, serverCfg)
		if err != nil {
			t.Fatalf("server: %v", err)
		}

		go func() {
			_, _ = client.Write([]byte("hello"))
		}()
		_ = server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		if _, err := server.Read(make([]byte, 64)); err == nil {
			t.Fatal("the server read a frame it has no key for")
		}
		select {
		case reason := <-reasons:
			seen[reason] = true
		default:
			t.Error("the server refused without recording a reason")
		}
		clientConn.Close()
		serverConn.Close()
	}
	return seen
}
