package diagnostics

import (
	"encoding/json/jsontext"
	"math"
	"runtime/metrics"
	"strconv"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// The names records go by in events.jsonl.
var (
	kindNames   = [...]string{kindStage: "stage", kindSocket: "socket", kindFlowOpen: "flow_open", kindFlowClose: "flow_close", kindRuntime: "runtime", kindSpike: "spike"}
	stageNames  = [...]string{stageRead: "transport_read", stageWrite: "transport_write"}
	sampleNames = [...]string{sampleTick: "periodic", sampleOpen: "open", sampleClose: "close"}
	spikeNames  = [...]string{spikeRTT: "rtt_excess", spikeRTO: "retransmit_timeout"}
)

// tcpFields is the order and the name, unit included, of every counter an
// event may carry; one the kernel did not give is left out.
var tcpFields = [...]struct {
	f    tcptune.CounterField
	name string
	get  func(*tcptune.Counters) uint64
}{
	{tcptune.CounterRTT, "rtt_us", func(c *tcptune.Counters) uint64 { return micros(c.RTT) }},
	{tcptune.CounterRTTVar, "rttvar_us", func(c *tcptune.Counters) uint64 { return micros(c.RTTVar) }},
	{tcptune.CounterMinRTT, "min_rtt_us", func(c *tcptune.Counters) uint64 { return micros(c.MinRTT) }},
	{tcptune.CounterRTO, "rto_us", func(c *tcptune.Counters) uint64 { return micros(c.RTO) }},
	{tcptune.CounterSinceData, "since_data_ms", func(c *tcptune.Counters) uint64 { return uint64(c.SinceData / time.Millisecond) }},
	{tcptune.CounterSinceAck, "since_ack_ms", func(c *tcptune.Counters) uint64 { return uint64(c.SinceAck / time.Millisecond) }},
	{tcptune.CounterState, "state", func(c *tcptune.Counters) uint64 { return uint64(c.State) }},
	{tcptune.CounterRetransmits, "retransmits", func(c *tcptune.Counters) uint64 { return uint64(c.Retransmits) }},
	{tcptune.CounterUnacked, "unacked_segments", func(c *tcptune.Counters) uint64 { return uint64(c.Unacked) }},
	{tcptune.CounterTotalRetrans, "total_retrans_segments", func(c *tcptune.Counters) uint64 { return uint64(c.TotalRetrans) }},
	{tcptune.CounterCongestionWindow, "cwnd_segments", func(c *tcptune.Counters) uint64 { return uint64(c.CongestionWindow) }},
	{tcptune.CounterCongestionWindowBytes, "cwnd_bytes", func(c *tcptune.Counters) uint64 { return uint64(c.CongestionWindowBytes) }},
	{tcptune.CounterInFlightBytes, "in_flight_bytes", func(c *tcptune.Counters) uint64 { return uint64(c.InFlightBytes) }},
	{tcptune.CounterNotSentBytes, "not_sent_bytes", func(c *tcptune.Counters) uint64 { return uint64(c.NotSentBytes) }},
	{tcptune.CounterSendWindow, "send_window_bytes", func(c *tcptune.Counters) uint64 { return uint64(c.SendWindow) }},
	{tcptune.CounterReceiveWindow, "receive_window_bytes", func(c *tcptune.Counters) uint64 { return uint64(c.ReceiveWindow) }},
	{tcptune.CounterBytesAcked, "bytes_acked", func(c *tcptune.Counters) uint64 { return c.BytesAcked }},
	{tcptune.CounterBytesReceived, "bytes_received", func(c *tcptune.Counters) uint64 { return c.BytesReceived }},
	{tcptune.CounterBytesSent, "bytes_sent", func(c *tcptune.Counters) uint64 { return c.BytesSent }},
	{tcptune.CounterBytesRetrans, "bytes_retrans", func(c *tcptune.Counters) uint64 { return c.BytesRetrans }},
	{tcptune.CounterTimeoutEpisodes, "timeout_episodes", func(c *tcptune.Counters) uint64 { return uint64(c.TimeoutEpisodes) }},
}

func micros(d time.Duration) uint64 { return uint64(d / time.Microsecond) }

// appendRecord appends rec to dst as one line of events.jsonl, newline
// included.
func appendRecord(dst []byte, rec *record) []byte {
	dst = append(dst, `{"seq":`...)
	dst = strconv.AppendUint(dst, rec.seq, 10)
	dst = append(dst, `,"elapsed_ns":`...)
	dst = strconv.AppendInt(dst, rec.mono, 10)
	dst = append(dst, `,"utc":"`...)
	dst = time.Unix(0, rec.wall).UTC().AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, `","flow":`...)
	if f := rec.flow; f != nil {
		dst = strconv.AppendUint(dst, uint64(f.id), 10)
		dst = appendString(append(dst, `,"leg":`...), f.leg)
		dst = appendString(append(dst, `,"transport":`...), f.transport)
	} else {
		dst = append(dst, `0,"leg":"process"`...)
	}
	dst = appendString(append(dst, `,"kind":`...), kindNames[rec.kind])
	dst = append(dst, `,"data":{`...)
	switch rec.kind {
	case kindStage:
		dst = appendString(append(dst, `"boundary":`...), stageNames[rec.what])
		dst = append(dst, `,"duration_ns":`...)
		dst = strconv.AppendInt(dst, rec.dur, 10)
		dst = append(dst, `,"bytes":`...)
		dst = strconv.AppendUint(dst, uint64(rec.n), 10)
		dst = appendBool(append(dst, `,"error":`...), rec.flags&flagError != 0)
		dst = appendBool(append(dst, `,"periodic":`...), rec.flags&flagPeriodic != 0)
		dst = appendBool(append(dst, `,"slow":`...), rec.flags&flagSlow != 0)
	case kindSocket:
		s := rec.payload.(*tcpSample)
		dst = appendString(append(dst, `"reason":`...), sampleNames[rec.what])
		dst = appendBool(append(dst, `,"available":`...), s.available)
		if rec.what == sampleTick {
			dst = append(dst, `,"read_wait_max_ns":`...)
			dst = strconv.AppendInt(dst, int64(s.readWait), 10)
		}
		if s.available {
			dst = appendCounters(append(dst, `,"tcp":`...), &s.counters)
		}
	case kindFlowOpen:
		dst = appendString(append(dst, `"local":`...), rec.flow.local)
		dst = appendString(append(dst, `,"remote":`...), rec.flow.remote)
	case kindFlowClose:
		t := rec.payload.(*flowTotals)
		dst = append(dst, `"read_calls":`...)
		dst = strconv.AppendUint(dst, t.reads, 10)
		dst = append(dst, `,"write_calls":`...)
		dst = strconv.AppendUint(dst, t.writes, 10)
	case kindRuntime:
		dst = appendRuntime(dst, rec.payload.(*runtimeSample))
	case kindSpike:
		dst = appendString(append(dst, `"reason":`...), spikeNames[rec.what])
		dst = appendString(append(dst, `,"incident_id":`...), rec.payload.(string))
	}
	return append(dst, "}}\n"...)
}

func appendCounters(dst []byte, c *tcptune.Counters) []byte {
	dst = append(dst, '{')
	first := true
	for _, f := range tcpFields {
		if !c.Known(f.f) {
			continue
		}
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = appendString(dst, f.name)
		dst = strconv.AppendUint(append(dst, ':'), f.get(c), 10)
	}
	return append(dst, '}')
}

func appendRuntime(dst []byte, s *runtimeSample) []byte {
	for i, name := range runtimeScalars {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(appendString(dst, name), ':')
		switch v := s.scalars[i]; v.Kind() {
		case metrics.KindUint64:
			dst = strconv.AppendUint(dst, v.Uint64(), 10)
		case metrics.KindFloat64:
			dst = appendFloat(dst, v.Float64())
		default:
			dst = append(dst, "null"...)
		}
	}
	from := 0
	for i, name := range runtimeHistograms {
		dst = append(appendString(append(dst, ','), name), ":["...)
		for j, n := range s.counts[from:s.ends[i]] {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = strconv.AppendUint(dst, n, 10)
		}
		dst = append(dst, ']')
		from = s.ends[i]
	}
	return dst
}

// appendFloat writes f as a JSON number, and null where JSON has none.
func appendFloat(dst []byte, f float64) []byte {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return append(dst, "null"...)
	}
	return strconv.AppendFloat(dst, f, 'g', -1, 64)
}

func appendString(dst []byte, s string) []byte {
	// The error says the string was not UTF-8; it is written with U+FFFD.
	dst, _ = jsontext.AppendQuote(dst, s)
	return dst
}

func appendBool(dst []byte, b bool) []byte { return strconv.AppendBool(dst, b) }
