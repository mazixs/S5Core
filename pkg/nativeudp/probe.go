package nativeudp

import "encoding/binary"

// Probe is what an extended probe says (docs/veil-spec.md, 10.6).
type Probe struct {
	Heard bool
	// Limit is the client's limit on the wire, 0 until it is found.
	Limit int
	// Size is 0 for a probe of the path. A probe of a size is Size bytes on
	// the wire and asks for an answer as long.
	Size int
	// Generation negotiates recoverable limits; zero retains the original protocol.
	Generation uint32
	// RouteProof advertises return-path verification; RouteEcho returns the
	// random token received at this address for this association.
	RouteProof bool
	RouteEcho  bool
	RouteToken [16]byte
}

const (
	probeHead          = 5
	answerHead         = 2
	recoveryMagic      = 0x4d545532
	recoveryProbeHead  = 13
	recoveryAnswerHead = 12
	routeMagic         = 0x52544531
	routeProbeHead     = recoveryProbeHead + 4 + 1 + 16
	routeAnswerHead    = recoveryAnswerHead + 4 + 1 + 16
)

// ParseProbe reads the data of a probe. extended is false for a probe of a
// client that predates the search, 2.3.0-rc1, whose only word is ProbeHeard.
func ParseProbe(data []byte) (p Probe, extended bool) {
	if len(data) < probeHead {
		return Probe{Heard: len(data) == 1 && data[0] == ProbeHeard}, false
	}
	p = Probe{
		Heard: data[0]&ProbeHeard != 0,
		Limit: int(binary.BigEndian.Uint16(data[1:])),
		Size:  int(binary.BigEndian.Uint16(data[3:])),
	}
	if len(data) >= recoveryProbeHead && binary.BigEndian.Uint32(data[5:]) == recoveryMagic {
		p.Generation = binary.BigEndian.Uint32(data[9:])
	}
	if len(data) >= routeProbeHead && binary.BigEndian.Uint32(data[13:]) == routeMagic && data[17] <= 1 {
		p.RouteProof, p.RouteEcho = true, data[17] == 1
		copy(p.RouteToken[:], data[18:34])
	}
	return p, true
}

// SealWriteProbe seals an extended probe into a pooled buffer and hands it to
// write. A probe of a size has no padding: zeros fill it to Size.
func (s *Session) SealWriteProbe(p Probe, write func([]byte) error) error {
	var head [routeProbeHead]byte
	n := probeHead
	if p.Heard {
		head[0] = ProbeHeard
	}
	binary.BigEndian.PutUint16(head[1:], uint16(p.Limit))
	binary.BigEndian.PutUint16(head[3:], uint16(p.Size))
	if p.Generation != 0 || p.RouteProof {
		binary.BigEndian.PutUint32(head[5:], recoveryMagic)
		binary.BigEndian.PutUint32(head[9:], p.Generation)
		n = recoveryProbeHead
	}
	if p.RouteProof {
		binary.BigEndian.PutUint32(head[13:], routeMagic)
		if p.RouteEcho {
			head[17] = 1
		}
		copy(head[18:], p.RouteToken[:])
		n = routeProbeHead
	}
	fill, space := 0, min(32, s.MaxPayload()-n)
	if p.Size != 0 {
		if p.Size > MaxWire || p.Size < s.overhead()+n {
			return ErrPacket
		}
		fill, space = p.Size-s.overhead()-n, 0
	}
	return s.sealWrite(KindProbe, head[:n], fill, space, write)
}

// SealWriteAnswer seals the answer to a probe that came wire bytes long:
// empty data for a probe that is not extended, a zero size with the usual
// padding for a probe of the path, and for a probe of a size exactly the
// size it asked for. The answer is never longer than the probe it reflects.
func (s *Session) SealWriteAnswer(p Probe, extended bool, wire int, write func([]byte) error) error {
	var head [recoveryAnswerHead]byte
	n := answerHead
	if !extended {
		return s.sealWrite(KindProbeAck, nil, 0, min(32, max(0, wire-s.overhead())), write)
	}
	if p.Generation != 0 {
		binary.BigEndian.PutUint32(head[2:], recoveryMagic)
		generation, limit := p.Generation, 0
		if p.Limit != 0 {
			generation, limit = s.NegotiatedLimit()
		}
		binary.BigEndian.PutUint32(head[6:], generation)
		binary.BigEndian.PutUint16(head[10:], uint16(limit))
		n = recoveryAnswerHead
	}
	if p.Size == 0 {
		// Never amplify a short control or malformed extension.
		return s.sealWrite(KindProbeAck, head[:n], 0, min(32, max(0, wire-s.overhead()-n)), write)
	}
	size := min(max(p.Size, s.overhead()+n), wire, MaxWire)
	if size < s.overhead()+n {
		return ErrPacket
	}
	binary.BigEndian.PutUint16(head[:], uint16(size))
	return s.sealWrite(KindProbeAck, head[:n], size-s.overhead()-n, 0, write)
}

// Answer includes an optional authenticated recovery acknowledgement.
type Answer struct {
	Size           int
	Generation     uint32
	Limit          int
	RouteChallenge bool
	RouteToken     [16]byte
}

func ParseAnswer(data []byte) (a Answer, extended bool) {
	if len(data) < answerHead {
		return a, false
	}
	a.Size = int(binary.BigEndian.Uint16(data))
	if len(data) >= recoveryAnswerHead && binary.BigEndian.Uint32(data[2:]) == recoveryMagic {
		a.Generation = binary.BigEndian.Uint32(data[6:])
		a.Limit = int(binary.BigEndian.Uint16(data[10:]))
	}
	if len(data) >= routeAnswerHead && binary.BigEndian.Uint32(data[12:]) == routeMagic && data[16] == 1 {
		a.RouteChallenge = true
		copy(a.RouteToken[:], data[17:33])
	}
	return a, true
}

// SealWriteChallenge reflects at most wire bytes. The candidate cannot
// receive application answers until it echoes this association's token.
func (s *Session) SealWriteChallenge(token [16]byte, wire int, write func([]byte) error) error {
	if wire < s.overhead()+routeAnswerHead {
		return ErrPacket
	}
	var head [routeAnswerHead]byte
	binary.BigEndian.PutUint32(head[2:], recoveryMagic)
	binary.BigEndian.PutUint32(head[12:], routeMagic)
	head[16] = 1
	copy(head[17:], token[:])
	return s.sealWrite(KindProbeAck, head[:], 0, min(32, wire-s.overhead()-len(head)), write)
}

// AnswerSize reads the data of an answer to a probe: the size it answers, 0
// for a probe of the path. extended is false for the empty answer of a
// server that predates the search.
func AnswerSize(data []byte) (size int, extended bool) {
	if len(data) < answerHead {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(data)), true
}

func (s *Session) sealWrite(kind byte, data []byte, fill, space int, write func([]byte) error) error {
	b := wirePool.Get().(*[MaxWire]byte)
	defer wirePool.Put(b)
	wire, err := s.seal(b[:0], kind, data, fill, space)
	if err != nil {
		return err
	}
	return write(wire)
}
