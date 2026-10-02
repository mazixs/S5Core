package nativeudp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

// The limit of native (docs/veil-spec.md, 10.7). The document states what the
// code does, and the code is changed after it, never before.
const specPath = "../../docs/veil-spec.md"

func TestTheSpecificationStatesTheLimitOfNative(t *testing.T) {
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("the format specification is missing: %v", err)
	}
	spec := string(b)
	for _, want := range []string{
		fmt.Sprintf("не длиннее %d байт (`MaxWire`)", MaxWire),
		fmt.Sprintf("сначала %d (`BASE_PLPMTU` RFC 8899)", BaseWire),
		fmt.Sprintf("`1200 + 22 + 26 = %d`", FloorWire),
		fmt.Sprintf("при `L < %d` правило то же", FloorWire),
		"flags[1] || uint16_BE(limit) || uint16_BE(size) || filler",
		"uint16_BE(size) || filler",
		fmt.Sprintf("но не меньше %d (ответ\nбез `filler`)", 8+2+16+answerHead),
		fmt.Sprintf("длиной %d-%d байт", controlLow, controlHigh),
		fmt.Sprintf("`%d - [0..%d]` байт", MaxWire, topSpread),
		fmt.Sprintf("из %d равных полос между 1200 и верхней", firstBands),
		fmt.Sprintf("каждой из %d равных полос между `lo` и `hi`", nextBands),
		fmt.Sprintf("сначала %d.", MaxWire+1),
		fmt.Sprintf("`hi - lo <= %d` или решили %d раунда", searchClose, searchRounds),
		fmt.Sprintf("не больше %d раз подряд", searchRetries),
		"ниже его не больше чем на 34 байта",
		"`IP_PMTUDISC_PROBE` и `IPV6_PMTUDISC_PROBE`",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("the specification does not state %q", want)
		}
	}
}

// Padding stays within the limit: a random pad that could reach past it made
// the loss by size a band as wide as the pad (docs/benchmarks/mtu-native-2026-09-26.md).
func TestPaddingNeverTakesADatagramPastTheLimit(t *testing.T) {
	for _, limit := range []int{BaseWire, FloorWire, 1331, 1372, MaxWire} {
		client, _ := pairOf(t, byte(limit))
		if !client.SetLimit(limit) || client.SetLimit(limit-10) {
			t.Fatalf("limit %d: the limit is set once", limit)
		}
		if got := client.MaxPayload(); got != limit-26 {
			t.Fatalf("limit %d: max payload %d, want %d", limit, got, limit-26)
		}
		longest := 0
		for size := 0; size <= client.MaxPayload(); size++ {
			for range 8 {
				wire, err := client.Seal(nil, KindData, make([]byte, size))
				if err != nil {
					t.Fatal(err)
				}
				longest = max(longest, len(wire))
				if len(wire) > limit {
					t.Fatalf("limit %d: a payload of %d is %d on the wire", limit, size, len(wire))
				}
			}
		}
		if longest != limit {
			t.Fatalf("limit %d: the longest datagram is %d", limit, longest)
		}
		if _, err := client.Seal(nil, KindData, make([]byte, client.MaxPayload()+1)); err == nil {
			t.Fatalf("limit %d: a payload past the limit was sealed", limit)
		}
	}
}

func TestTheLimitStaysWithinTheRangeOfTheSearch(t *testing.T) {
	for _, c := range []struct{ set, want int }{{1, BaseWire}, {1300, 1300}, {65535, MaxWire}} {
		s, _ := pair(t)
		s.SetLimit(c.set)
		if s.Limit() != c.want {
			t.Errorf("limit %d is %d, want %d", c.set, s.Limit(), c.want)
		}
	}
}

// open is what the peer reads of wire, with how long it was.
func open(t *testing.T, s *Session, wire []byte) (Packet, int) {
	t.Helper()
	n := len(wire)
	p, err := s.Open(bytes.Clone(wire))
	if err != nil {
		t.Fatal(err)
	}
	return p, n
}

func sealed(t *testing.T, seal func(write func([]byte) error) error) []byte {
	t.Helper()
	var wire []byte
	if err := seal(func(b []byte) error { wire = bytes.Clone(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return wire
}

// A probe of a size is that long on the wire, and so is its answer.
func TestAProbeOfASizeIsAnsweredAtItsSize(t *testing.T) {
	client, server := pair(t)
	for _, size := range []int{controlLow, controlHigh, BaseWire, 1357, MaxWire} {
		wire := sealed(t, func(w func([]byte) error) error { return client.SealWriteProbe(Probe{Size: size}, w) })
		if len(wire) != size {
			t.Fatalf("a probe of %d is %d on the wire", size, len(wire))
		}
		p, n := open(t, server, wire)
		probe, extended := ParseProbe(p.Data)
		if !extended || probe != (Probe{Size: size}) {
			t.Fatalf("probe of %d read as %+v (extended %v)", size, probe, extended)
		}
		answer := sealed(t, func(w func([]byte) error) error { return server.SealWriteAnswer(probe, extended, n, w) })
		if len(answer) != size {
			t.Fatalf("the answer to a probe of %d is %d on the wire", size, len(answer))
		}
		a, _ := open(t, client, answer)
		if got, ok := AnswerSize(a.Data); !ok || got != size {
			t.Fatalf("the answer to a probe of %d says %d (%v)", size, got, ok)
		}
	}
	if err := client.SealWriteProbe(Probe{Size: MaxWire + 1}, func([]byte) error { return nil }); err == nil {
		t.Fatal("a probe past MaxWire was sealed")
	}
}

// The answer reflects the probe and is never longer, whatever size the probe
// asks for: the node does not amplify.
func TestAnAnswerIsNeverLongerThanItsProbe(t *testing.T) {
	client, server := pair(t)
	for _, asked := range []int{1, 40, 1000, MaxWire, 65535} {
		var head [probeHead]byte
		binary.BigEndian.PutUint16(head[3:], uint16(asked))
		wire, err := client.Seal(nil, KindProbe, head[:])
		if err != nil {
			t.Fatal(err)
		}
		p, n := open(t, server, wire)
		probe, extended := ParseProbe(p.Data)
		answer := sealed(t, func(w func([]byte) error) error { return server.SealWriteAnswer(probe, extended, n, w) })
		if len(answer) > n {
			t.Fatalf("a probe of %d asking for %d got an answer of %d", n, asked, len(answer))
		}
		a, _ := open(t, client, answer)
		if got, _ := AnswerSize(a.Data); got != len(answer) {
			t.Fatalf("the answer of %d says %d", len(answer), got)
		}
	}
}

// A probe of 2.3.0-rc1 gets the empty answer it expects, and the empty answer
// is how the client knows a server without the search.
func TestAProbeOfAnOlderClientGetsAnEmptyAnswer(t *testing.T) {
	client, server := pair(t)
	for _, data := range [][]byte{nil, {ProbeHeard}, {ProbeHeard, 0}, {0, 0, 0, 0}} {
		wire, err := client.Seal(nil, KindProbe, data)
		if err != nil {
			t.Fatal(err)
		}
		p, n := open(t, server, wire)
		probe, extended := ParseProbe(p.Data)
		if extended || probe.Heard != bytes.Equal(data, []byte{ProbeHeard}) {
			t.Fatalf("probe %x read as %+v (extended %v)", data, probe, extended)
		}
		a, _ := open(t, client, sealed(t, func(w func([]byte) error) error { return server.SealWriteAnswer(probe, extended, n, w) }))
		if len(a.Data) != 0 {
			t.Fatalf("probe %x got the answer %x", data, a.Data)
		}
		if _, ok := AnswerSize(a.Data); ok {
			t.Fatal("an empty answer read as one of a server with the search")
		}
	}
	p, _ := open(t, server, sealed(t, func(w func([]byte) error) error {
		return client.SealWriteProbe(Probe{Heard: true, Limit: 1333}, w)
	}))
	if probe, extended := ParseProbe(p.Data); !extended || probe != (Probe{Heard: true, Limit: 1333}) {
		t.Fatalf("an extended probe read as %+v", probe)
	}
}

// The limit a probe announces bounds what the hub sends the client, padding
// included, and only the first one counts.
func TestTheLimitOfTheClientBoundsTheAnswersOfTheHub(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c := dialHub(t, hub)
	var b [MaxWire + 1]byte
	probe := func(p Probe) int {
		t.Helper()
		if err := client.SealWriteProbe(p, func(w []byte) error { _, err := c.Write(w); return err }); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		a, err := client.Open(b[:n])
		if err != nil || a.Kind != KindProbeAck {
			t.Fatalf("probe %+v: %v", p, err)
		}
		size, _ := AnswerSize(a.Data)
		return size
	}
	if got := probe(Probe{Size: 1377}); got != 1377 {
		t.Fatalf("a probe of 1377 was answered as %d", got)
	}
	if registered.Limit() != MaxWire {
		t.Fatal("a probe without a limit set one")
	}
	probe(Probe{Limit: 1250})
	probe(Probe{Limit: 1300})
	if registered.Limit() != 1250 || registered.MaxPayload() != 1250-26 {
		t.Fatalf("limit %d, max payload %d after the client announced 1250", registered.Limit(), registered.MaxPayload())
	}
	for range 64 {
		if err := hub.Send(registered, KindData, make([]byte, registered.MaxPayload()-rand.IntN(40))); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		if n > 1250 {
			t.Fatalf("the hub sent %d bytes past a limit of 1250", n)
		}
	}
	if hub.Send(registered, KindData, make([]byte, registered.MaxPayload()+1)) == nil {
		t.Fatal("the hub sent a payload past the limit")
	}
}

// search runs a search on a path that carries datagrams up to path bytes
// both ways and loses each probe with the given chance. It returns the limit
// and the rounds it took.
func search(r *rand.Rand, path int, loss float64) (*Search, int) {
	s := NewSearch(r.IntN)
	for rounds := 1; ; rounds++ {
		for _, size := range s.Round() {
			if size <= path && r.Float64() >= loss && r.Float64() >= loss {
				s.Answered(size)
			}
		}
		if s.End() {
			return s, rounds
		}
	}
}

func TestTheSearchFindsTheLimitOfThePath(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for path := BaseWire; path <= 1500; path++ {
		for range 200 {
			s, rounds := search(r, path, 0)
			l, top := s.Limit(), min(path, MaxWire)
			if l > top || l < top-34 {
				t.Fatalf("path %d: limit %d", path, l)
			}
			if rounds > searchRounds || s.Sent() != 7+4*(rounds-1) {
				t.Fatalf("path %d: %d rounds, %d probes", path, rounds, s.Sent())
			}
			if path >= MaxWire && (rounds != 1 || l < MaxWire-topSpread) {
				t.Fatalf("path %d: %d rounds to limit %d", path, rounds, l)
			}
		}
	}
}

// A lost probe costs precision, never a limit past the path.
func TestALostProbeNeverTakesTheLimitPastThePath(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for path := BaseWire; path <= MaxWire; path += 7 {
		for range 200 {
			s, rounds := search(r, path, 0.1)
			if s.Limit() > path {
				t.Fatalf("path %d: limit %d", path, s.Limit())
			}
			if rounds > searchRounds+searchRetries*searchRounds {
				t.Fatalf("path %d: %d rounds", path, rounds)
			}
		}
	}
}

// A round whose control is lost says nothing of the sizes, and a path that
// answers nothing ends at BaseWire after searchRetries rounds.
func TestARoundWithoutItsControlDecidesNothing(t *testing.T) {
	s := NewSearch(rand.IntN)
	sizes := s.Round()
	for _, size := range sizes[:len(sizes)-1] {
		s.Answered(size)
	}
	if s.End() || s.Limit() != BaseWire {
		t.Fatalf("a round without its control moved the limit to %d", s.Limit())
	}
	for i := 2; i <= searchRetries; i++ {
		s.Round()
		if over := s.End(); over != (i == searchRetries) {
			t.Fatalf("round %d without an answer: over %v", i, over)
		}
	}
	if s.Limit() != BaseWire {
		t.Fatalf("a path that answered nothing has the limit %d", s.Limit())
	}
}

// The probes and their answers are a corpus like any other the checklist
// reads: no constant bytes at fixed places, no one length that stands out.
func TestProbesAndAnswersHaveNoConstantShape(t *testing.T) {
	client, server := pair(t)
	r := rand.New(rand.NewPCG(5, 6))
	var corpus [][]byte
	add := func(seal func(write func([]byte) error) error) {
		corpus = append(corpus, sealed(t, seal))
	}
	answer := func(wire []byte) {
		p, n := open(t, server, wire)
		probe, extended := ParseProbe(p.Data)
		add(func(w func([]byte) error) error { return server.SealWriteAnswer(probe, extended, n, w) })
	}
	for i := 0; i < 400; i++ {
		s, _ := search(r, BaseWire+r.IntN(MaxWire-BaseWire+100), 0)
		// The sizes a search sent, replayed through the codec.
		for range s.Sent() / 4 {
			size := BaseWire + 1 + r.IntN(MaxWire-BaseWire)
			add(func(w func([]byte) error) error { return client.SealWriteProbe(Probe{Size: size}, w) })
			answer(corpus[len(corpus)-1])
		}
		control := controlLow + r.IntN(controlHigh-controlLow+1)
		add(func(w func([]byte) error) error { return client.SealWriteProbe(Probe{Size: control}, w) })
		answer(corpus[len(corpus)-1])
		for range 3 {
			add(func(w func([]byte) error) error {
				return client.SealWriteProbe(Probe{Heard: r.IntN(2) == 0, Limit: s.Limit()}, w)
			})
			answer(corpus[len(corpus)-1])
		}
	}
	lengths := stealth.Lengths(corpus)
	if lengths.TopShare >= 0.05 {
		t.Errorf("probes and answers: %v", lengths)
	}
	if findings := stealth.PositionalUniformity(corpus, 64); len(findings) != 0 {
		t.Errorf("probes and answers have fixed bytes: %v", findings)
	}
}
