package tcptune

import (
	"errors"
	"net"
	"time"
)

// CounterField names one field of Counters.
type CounterField uint32

// The fields of Counters. A field is the same quantity in the same unit on
// every system that sets it: Linux counts the congestion window in segments
// and Windows in bytes, so they are two fields.
const (
	CounterRTT CounterField = 1 << iota
	CounterRTTVar
	CounterMinRTT
	CounterRTO
	CounterSinceData
	CounterSinceAck
	CounterState
	CounterRetransmits
	CounterUnacked
	CounterTotalRetrans
	CounterCongestionWindow
	CounterCongestionWindowBytes
	CounterInFlightBytes
	CounterNotSentBytes
	CounterSendWindow
	CounterReceiveWindow
	CounterBytesAcked
	CounterBytesReceived
	CounterBytesSent
	CounterBytesRetrans
	CounterTimeoutEpisodes
)

// Counters is what the latency diagnostics read about a socket: more than
// Info, and not on the forwarding path. Has says which fields the kernel
// gave; one it does not have (an older kernel, another system) stays zero
// and is not in Has.
type Counters struct {
	Has CounterField
	// RTT, RTTVar and MinRTT are the smoothed round trip time, its variance
	// and the lowest seen; RTO is the retransmit timeout.
	RTT, RTTVar, MinRTT, RTO time.Duration
	// SinceData and SinceAck are the time since the peer last sent data and
	// last acknowledged anything.
	SinceData, SinceAck time.Duration
	// BytesAcked, BytesReceived, BytesSent and BytesRetrans count the life of
	// the connection; on Windows BytesRetrans is 32 bits wide.
	BytesAcked, BytesReceived, BytesSent, BytesRetrans uint64
	// Unacked, TotalRetrans and CongestionWindow are in segments.
	Unacked, TotalRetrans, CongestionWindow uint32
	// CongestionWindowBytes, InFlightBytes, NotSentBytes, SendWindow and
	// ReceiveWindow are in bytes.
	CongestionWindowBytes, InFlightBytes, NotSentBytes, SendWindow, ReceiveWindow uint32
	// TimeoutEpisodes counts the retransmit timeouts of the connection.
	TimeoutEpisodes uint32
	// Retransmits is how many times in a row the retransmit timer has fired.
	Retransmits uint8
	// State is the TCP state in Linux numbering.
	State uint8
}

// Known reports whether the kernel gave every field in f.
func (c *Counters) Known(f CounterField) bool { return c.Has&f == f }

// errShortInfo means the kernel's answer ends before the fields every
// version of it has: an emulator that answers with an int does that.
var errShortInfo = errors.New("tcptune: the kernel's TCP information is too short")

// CountersOf reads Counters for the socket under c, from the same read as
// InfoOf. The error is ErrNoSocket without a socket, matches net.ErrClosed
// for a closed one, and is errUnsupported where the system does not say.
func CountersOf(c net.Conn) (Counters, error) {
	sc, err := Socket(c)
	if err != nil {
		return Counters{}, err
	}
	return countersOf(sc)
}
