package tcptune

import (
	"net"
	"time"
)

// Info is what the kernel says about the TCP connection under a tunnel at the
// moment it is asked: whether the path still carries traffic or the peer
// merely stopped sending. A connection the server closes for silence reads
// differently in the two cases: on a dead path it has segments the peer never
// acknowledged and a retransmit timer that keeps firing, on a quiet client
// everything is acknowledged and only the time since the last data grows.
type Info struct {
	// RTT is the smoothed round trip time.
	RTT time.Duration
	// Unacked is the number of segments sent and not acknowledged yet.
	Unacked uint32
	// Retransmits is how many times in a row the retransmit timer has fired
	// without an acknowledgement; zero on a healthy path.
	Retransmits uint8
	// SinceData and SinceAck are the time since the peer last sent data and
	// last acknowledged anything.
	SinceData, SinceAck time.Duration
}

// InfoOf reads the TCP state of the socket under c. ok is false where the
// kernel does not say: not Linux, no socket under the connection, or one that
// is already closed.
func InfoOf(c net.Conn) (Info, bool) {
	sc, err := Socket(c)
	if err != nil {
		return Info{}, false
	}
	return infoOf(sc)
}
