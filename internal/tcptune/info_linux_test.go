package tcptune

import (
	"testing"
	"time"
)

// A connection that has just moved data both ways is the healthy case the
// numbers are read against: no timer firing, and the time since the peer last
// spoke is a moment, not seconds. Unacked is not asserted: the last segment
// of the exchange may still be waiting for its acknowledgement.
func TestInfoOfALivePath(t *testing.T) {
	c, s := tcpPair(t)
	b := []byte{0}
	for range 5 {
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Read(b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	info, ok := InfoOf(s)
	if !ok {
		t.Fatal("no TCP info for a live socket")
	}
	if info.Retransmits != 0 {
		t.Errorf("a healthy path shows trouble: %+v", info)
	}
	if info.SinceData > 2*time.Second || info.SinceAck > 2*time.Second {
		t.Errorf("a path that has just spoken is silent for seconds: %+v", info)
	}
	if info.RTT <= 0 {
		t.Errorf("no round trip measured: %+v", info)
	}
	// Each answer acknowledges the byte it answers.
	if sent, ok := InfoOf(c); !ok || sent.BytesAcked < 5 {
		t.Errorf("five bytes answered, %d acknowledged", sent.BytesAcked)
	}
}

func TestAClosedSocketHasNoInfo(t *testing.T) {
	_, s := tcpPair(t)
	_ = s.Close()
	if info, ok := InfoOf(s); ok {
		t.Fatalf("a closed socket has TCP info: %+v", info)
	}
}

func TestAPeerThatClosedLeavesTheSocketOutOfEstablished(t *testing.T) {
	c, s := tcpPair(t)
	if info, ok := InfoOf(c); !ok || info.State != StateEstablished {
		t.Fatalf("a live socket is in state %d, ok=%v", info.State, ok)
	}
	// Bytes ahead of the FIN, as a TLS close_notify would be: the state
	// still says the peer is gone.
	if _, err := s.Write([]byte("alert")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, ok := InfoOf(c)
		if ok && info.State != StateEstablished {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket is still established after the peer closed: %+v", info)
		}
		time.Sleep(time.Millisecond)
	}
}
