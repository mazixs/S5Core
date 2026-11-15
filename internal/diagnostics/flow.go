package diagnostics

import (
	"net"
	"time"
)

// Flow is a selected outer socket, for what its reads and writes do not
// show: the setup of the tunnel on it and the native UDP path beside it. The
// zero Flow, with diagnostics off or for a socket the recorder did not
// select, records nothing; so does a Flow whose socket is no longer sampled
// or whose recorder stopped.
type Flow struct {
	r *recorder
	s *socket
}

// FlowOf returns the flow of c's socket when c is a socket the recorder
// selected and still samples, found through its wrappers, and the zero Flow
// otherwise: a related socket has none. Off, it costs one atomic load.
func FlowOf(c net.Conn) Flow {
	if current.Load() == nil {
		return Flow{}
	}
	return flowOf(c)
}

// flowOf is FlowOf past its check.
func flowOf(c net.Conn) Flow {
	r := current.Load()
	if r == nil || r.stopped.Load() {
		return Flow{}
	}
	s := socketUnder(c)
	if s == nil {
		return Flow{}
	}
	r.mu.Lock()
	_, sampled := r.sockets[s]
	r.mu.Unlock()
	if !sampled || s.outer != nil {
		return Flow{}
	}
	return Flow{r: r, s: s}
}

// TunnelSetup records a tunnel on the socket that is ready: its request was
// accepted after setup, on a spare transport, dialed before it, if spare.
func (f Flow) TunnelSetup(setup time.Duration, spare bool) {
	if f.s != nil {
		var flags uint8
		if spare {
			flags = flagSpare
		}
		f.push(record{kind: kindStage, what: stageSetup, flags: flags, dur: int64(setup)}, false)
	}
}

// NativeVerified records the first answer of the native UDP path beside the
// socket, with the addresses of the client's UDP socket.
func (f Flow) NativeVerified(local, remote net.Addr) {
	if f.s != nil {
		f.nativeVerified(local, remote)
	}
}

func (f Flow) nativeVerified(local, remote net.Addr) {
	if f.r.stopped.Load() {
		return
	}
	f.push(record{kind: kindNativePath, what: pathVerified, payload: &pathAddrs{local: local.String(), remote: remote.String()}}, false)
}

// NativeLost records the loss of the native path after unanswered probes in
// a row, and claims an incident: the worker takes the claim at its next tick
// as a spike of the socket, under the same cooldown.
func (f Flow) NativeLost(unanswered int) {
	if f.s != nil {
		f.push(record{kind: kindNativePath, what: pathLost, n: uint32(unanswered)}, true)
	}
}

// NativeRestored records an answer of the native path after its loss.
func (f Flow) NativeRestored() {
	if f.s != nil {
		f.push(record{kind: kindNativePath, what: pathRestored}, false)
	}
}

// NativeProbe records the round trip of a probe of the native path whose
// answer is known to be its own.
func (f Flow) NativeProbe(rtt time.Duration) {
	if f.s != nil {
		f.push(record{kind: kindNativeProbe, dur: int64(rtt)}, false)
	}
}

// push records rec on the socket while it is sampled, and with claim leaves
// the worker the claim of an incident.
func (f Flow) push(rec record, claim bool) {
	r := f.r
	if r.stopped.Load() {
		return
	}
	rec.flow = f.s.flow
	r.mu.Lock()
	if _, sampled := r.sockets[f.s]; sampled {
		r.pushLocked(rec)
		if claim {
			r.claims = append(r.claims, f.s)
		}
	}
	r.mu.Unlock()
}
