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
}

func TestAClosedSocketHasNoInfo(t *testing.T) {
	_, s := tcpPair(t)
	_ = s.Close()
	if info, ok := InfoOf(s); ok {
		t.Fatalf("a closed socket has TCP info: %+v", info)
	}
}
