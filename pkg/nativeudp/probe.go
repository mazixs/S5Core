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
}

const (
	probeHead  = 5
	answerHead = 2
)

// ParseProbe reads the data of a probe. extended is false for a probe of a
// client that predates the search, 2.3.0-rc1, whose only word is ProbeHeard.
func ParseProbe(data []byte) (p Probe, extended bool) {
	if len(data) < probeHead {
		return Probe{Heard: len(data) == 1 && data[0] == ProbeHeard}, false
	}
	return Probe{
		Heard: data[0]&ProbeHeard != 0,
		Limit: int(binary.BigEndian.Uint16(data[1:])),
		Size:  int(binary.BigEndian.Uint16(data[3:])),
	}, true
}

// SealWriteProbe seals an extended probe into a pooled buffer and hands it to
// write. A probe of a size has no padding: zeros fill it to Size.
func (s *Session) SealWriteProbe(p Probe, write func([]byte) error) error {
	var head [probeHead]byte
	if p.Heard {
		head[0] = ProbeHeard
	}
	binary.BigEndian.PutUint16(head[1:], uint16(p.Limit))
	binary.BigEndian.PutUint16(head[3:], uint16(p.Size))
	fill, space := 0, min(32, s.MaxPayload()-probeHead)
	if p.Size != 0 {
		if p.Size > MaxWire || p.Size < s.overhead()+probeHead {
			return ErrPacket
		}
		fill, space = p.Size-s.overhead()-probeHead, 0
	}
	return s.sealWrite(KindProbe, head[:], fill, space, write)
}

// SealWriteAnswer seals the answer to a probe that came wire bytes long:
// empty data for a probe that is not extended, a zero size with the usual
// padding for a probe of the path, and for a probe of a size exactly the
// size it asked for. The answer is never longer than the probe it reflects.
func (s *Session) SealWriteAnswer(p Probe, extended bool, wire int, write func([]byte) error) error {
	var head [answerHead]byte
	switch {
	case !extended:
		return s.sealWrite(KindProbeAck, nil, 0, min(32, s.MaxPayload()), write)
	case p.Size == 0:
		return s.sealWrite(KindProbeAck, head[:], 0, min(32, s.MaxPayload()-answerHead), write)
	}
	size := min(max(p.Size, s.overhead()+answerHead), wire, MaxWire)
	binary.BigEndian.PutUint16(head[:], uint16(size))
	return s.sealWrite(KindProbeAck, head[:], size-s.overhead()-answerHead, 0, write)
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
