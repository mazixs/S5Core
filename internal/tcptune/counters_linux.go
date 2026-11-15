package tcptune

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func countersOf(sc syscall.Conn) (Counters, error) {
	var ti unix.TCPInfo
	n, err := readTCPInfo(sc, &ti)
	if err != nil {
		return Counters{}, err
	}
	c, ok := decodeCounters(&ti, n)
	if !ok {
		return Counters{}, errShortInfo
	}
	return c, nil
}

// decodeCounters reads ti as far as the n bytes the kernel wrote into it.
// A field past tcpi_rtt is set only where the answer reaches its end: a
// kernel writes the part of struct tcp_info it knows.
func decodeCounters(ti *unix.TCPInfo, n uint32) (Counters, bool) {
	if n < infoBaseLen {
		return Counters{}, false
	}
	c := Counters{
		Has: CounterRTT | CounterRTO | CounterSinceData | CounterSinceAck |
			CounterState | CounterRetransmits | CounterUnacked,
		RTT:         time.Duration(ti.Rtt) * time.Microsecond,
		RTO:         time.Duration(ti.Rto) * time.Microsecond,
		SinceData:   time.Duration(ti.Last_data_recv) * time.Millisecond,
		SinceAck:    time.Duration(ti.Last_ack_recv) * time.Millisecond,
		State:       ti.State,
		Retransmits: ti.Retransmits,
		Unacked:     ti.Unacked,
	}
	reaches := func(off, size uintptr) bool { return uintptr(n) >= off+size }
	if reaches(unsafe.Offsetof(ti.Rttvar), unsafe.Sizeof(ti.Rttvar)) {
		c.RTTVar = time.Duration(ti.Rttvar) * time.Microsecond
		c.Has |= CounterRTTVar
	}
	if reaches(unsafe.Offsetof(ti.Snd_cwnd), unsafe.Sizeof(ti.Snd_cwnd)) {
		c.CongestionWindow = ti.Snd_cwnd
		c.Has |= CounterCongestionWindow
	}
	if reaches(unsafe.Offsetof(ti.Total_retrans), unsafe.Sizeof(ti.Total_retrans)) {
		c.TotalRetrans = ti.Total_retrans
		c.Has |= CounterTotalRetrans
	}
	// Linux 4.1.
	if reaches(unsafe.Offsetof(ti.Bytes_acked), unsafe.Sizeof(ti.Bytes_acked)) {
		c.BytesAcked = ti.Bytes_acked
		c.Has |= CounterBytesAcked
	}
	if reaches(unsafe.Offsetof(ti.Bytes_received), unsafe.Sizeof(ti.Bytes_received)) {
		c.BytesReceived = ti.Bytes_received
		c.Has |= CounterBytesReceived
	}
	// Linux 4.6.
	if reaches(unsafe.Offsetof(ti.Notsent_bytes), unsafe.Sizeof(ti.Notsent_bytes)) {
		c.NotSentBytes = ti.Notsent_bytes
		c.Has |= CounterNotSentBytes
	}
	if reaches(unsafe.Offsetof(ti.Min_rtt), unsafe.Sizeof(ti.Min_rtt)) {
		c.MinRTT = time.Duration(ti.Min_rtt) * time.Microsecond
		c.Has |= CounterMinRTT
	}
	// Linux 4.19.
	if reaches(unsafe.Offsetof(ti.Bytes_sent), unsafe.Sizeof(ti.Bytes_sent)) {
		c.BytesSent = ti.Bytes_sent
		c.Has |= CounterBytesSent
	}
	if reaches(unsafe.Offsetof(ti.Bytes_retrans), unsafe.Sizeof(ti.Bytes_retrans)) {
		c.BytesRetrans = ti.Bytes_retrans
		c.Has |= CounterBytesRetrans
	}
	// Later kernels.
	if reaches(unsafe.Offsetof(ti.Snd_wnd), unsafe.Sizeof(ti.Snd_wnd)) {
		c.SendWindow = ti.Snd_wnd
		c.Has |= CounterSendWindow
	}
	if reaches(unsafe.Offsetof(ti.Rcv_wnd), unsafe.Sizeof(ti.Rcv_wnd)) {
		c.ReceiveWindow = ti.Rcv_wnd
		c.Has |= CounterReceiveWindow
	}
	return c, true
}
