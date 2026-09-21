package stealth

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// randomCorpus builds deterministic pseudo-random packets: the instrument has
// to give the same answer on every run, and a seeded generator is the cheapest
// way to be sure a finding is a property of the data and not of the day.
func randomCorpus(t *testing.T, streams, size int, seed uint64) [][]byte {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, 0x5eed))
	corpus := make([][]byte, streams)
	for i := range corpus {
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(r.UintN(256))
		}
		corpus[i] = p
	}
	return corpus
}

// The rule that makes the old entropy test the wrong instrument: a stream
// that looks perfectly random matches no exemption and is the one a censor
// blocks. "Indistinguishable from noise" is not a goal, it is the signature.
func TestAPerfectlyRandomPacketIsTheOneThatGetsBlocked(t *testing.T) {
	corpus := randomCorpus(t, 200, 1400, 1)
	res := RunLevel1(corpus)

	if res.Blocked != res.Streams {
		t.Errorf("%d of %d random streams found an exemption; the level-1 policy blocks random traffic",
			res.Streams-res.Blocked, res.Streams)
	}
	if res.MeanBitsPerByte < RandomBandLow || res.MeanBitsPerByte > RandomBandHigh {
		t.Errorf("random data measured %.3f bits per byte, outside the band [%.1f, %.1f] it defines",
			res.MeanBitsPerByte, RandomBandLow, RandomBandHigh)
	}
}

func TestEachExemptionFiresOnItsOwnShape(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 3))
	randomTail := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			// Bytes with the high bit set and no printable runs: random
			// enough for the popcount band, never mistaken for text.
			b[i] = byte(r.UintN(128)) | 0x80
		}
		return b
	}

	tests := []struct {
		name   string
		packet []byte
		want   Exemption
	}{
		{"all zeros", make([]byte, 600), Ex1PopcountOutsideRandomBand},
		{"all ones", bytes.Repeat([]byte{0xff}, 600), Ex1PopcountOutsideRandomBand},
		{"text command line", append([]byte("USER anonymous"), randomTail(600)...), Ex2FirstSixPrintable},
		{"mostly text", append(bytes.Repeat([]byte("hello "), 60), randomTail(300)...), Ex2FirstSixPrintable},
		{"binary with a long string", append(append(randomTail(300), []byte("Mozilla/5.0 (Windows NT 10.0)")...), randomTail(300)...), Ex4LongPrintableRun},
		{"TLS record", append([]byte{0x16, 0x03, 0x01}, randomTail(600)...), Ex5KnownProtocolPrefix},
		// The TLS rule constrains three bytes, not two (USENIX Sec 2023,
		// section 4.3: [\x16-\x17]\x03[\x00-\x09]). A checklist that
		// stopped at two would call the next case exempt and the censor
		// would block it - the expensive direction of that mistake, since
		// the countermeasure in docs/field/stealth.md is a TLS record
		// header put there on purpose.
		{"TLS application data record", append([]byte{0x17, 0x03, 0x03}, randomTail(600)...), Ex5KnownProtocolPrefix},
		{"TLS-like prefix with an impossible version", append([]byte{0x16, 0x03, 0xff}, randomTail(600)...), ExNone},
		{"random", randomCorpus(t, 1, 600, 7)[0], ExNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Exempt(tt.packet); got != tt.want {
				t.Errorf("Exempt() = %v, want %v (%.3f bits per byte)", got, tt.want, BitsPerByte(tt.packet))
			}
		})
	}
}

// The positional check is the part that sees a header. It has to stay quiet on
// data that has none, or every real finding drowns in noise.
func TestPositionalUniformityIsQuietOnRandomCorpora(t *testing.T) {
	for seed := uint64(0); seed < 20; seed++ {
		corpus := randomCorpus(t, 1000, 64, seed)
		if f := PositionalUniformity(corpus, 64); len(f) != 0 {
			t.Errorf("seed %d: random corpus produced findings: %v", seed, f)
		}
	}
}

func TestPositionalUniformityFindsAConstantField(t *testing.T) {
	corpus := randomCorpus(t, 1000, 64, 42)
	const offset = 3
	for _, p := range corpus {
		p[offset] = 0x00
	}

	findings := PositionalUniformity(corpus, 64)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly the planted one: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Offset != offset || f.Value != 0x00 || f.Share != 1 || f.Distinct != 1 {
		t.Errorf("finding does not describe the planted field: %s", f)
	}
}

// A field that is merely biased, not constant, is the harder and more
// realistic case: a version byte that takes two values, a counter that moves
// slowly.
func TestPositionalUniformityFindsABiasedField(t *testing.T) {
	corpus := randomCorpus(t, 1000, 64, 11)
	const offset = 17
	for i, p := range corpus {
		if i%10 != 0 {
			p[offset] = 0x2a
		}
	}

	findings := PositionalUniformity(corpus, 64)
	if len(findings) != 1 || findings[0].Offset != offset {
		t.Fatalf("a field present in 90%% of streams was not found: %v", findings)
	}
}

func TestLengthsDescribeThePeak(t *testing.T) {
	fixed := make([][]byte, 100)
	for i := range fixed {
		fixed[i] = make([]byte, 1500)
	}
	if r := Lengths(fixed); r.TopShare != 1 || r.Distinct != 1 || r.TopLength != 1500 {
		t.Errorf("a constant length was not reported as one peak: %s", r)
	}

	spread := make([][]byte, 1000)
	for i := range spread {
		spread[i] = make([]byte, 1000+i%257)
	}
	r := Lengths(spread)
	if r.Distinct != 257 {
		t.Errorf("got %d distinct lengths, want 257: %s", r.Distinct, r)
	}
	if r.TopShare > 0.01 {
		t.Errorf("a spread distribution still has a peak of %.1f%%: %s", r.TopShare*100, r)
	}
}

func TestIntervalsFindAFixedPeriod(t *testing.T) {
	fixed := make([]float64, 100)
	for i := range fixed {
		fixed[i] = 45.0
	}
	if r := Intervals(fixed, 1); r.TopShare != 1 {
		t.Errorf("a fixed keepalive period was not reported as a constant: %+v", r)
	}

	r := rand.New(rand.NewPCG(5, 6))
	jittered := make([]float64, 1000)
	for i := range jittered {
		jittered[i] = 45 + r.Float64()*30
	}
	if got := Intervals(jittered, 1); got.TopShare > 0.1 {
		t.Errorf("a jittered period concentrated %.1f%% in one bucket: %+v", got.TopShare*100, got)
	}
}
