package stealth

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Level 2 is about what a protocol leaks about itself once a censor has more
// than one connection to look at: a byte that is always the same at the same
// offset, a length that repeats, an interval that never varies. None of it
// shows up in a single-connection entropy measurement, which is why the test
// this package replaces could not see any of it.

// PositionFinding is one offset whose byte values are not distributed the way
// a random field would be.
type PositionFinding struct {
	Offset int
	// Value is the byte value that appeared too often, and Count how often.
	Value byte
	Count int
	// Share is Count divided by the number of streams.
	Share float64
	// Distinct is how many different values that offset ever took.
	Distinct int
}

func (f PositionFinding) String() string {
	return fmt.Sprintf("offset %d: 0x%02x in %d streams (%.1f%%), %d distinct values",
		f.Offset, f.Value, f.Count, f.Share*100, f.Distinct)
}

// PositionalUniformity looks at the first prefix bytes of every stream and
// reports the offsets where some byte value occurs far more often than a
// uniform field would produce.
//
// The threshold is derived from the corpus size rather than chosen: see
// overrepresentationThreshold. Offsets shorter than prefix in a given stream
// are skipped, so a corpus of mixed-length packets still works.
func PositionalUniformity(corpus [][]byte, prefix int) []PositionFinding {
	if len(corpus) == 0 || prefix <= 0 {
		return nil
	}

	var findings []PositionFinding
	for off := 0; off < prefix; off++ {
		var counts [256]int
		total := 0
		for _, p := range corpus {
			if off >= len(p) {
				continue
			}
			counts[p[off]]++
			total++
		}
		if total == 0 {
			continue
		}

		limit := overrepresentationThreshold(total, prefix*256)
		distinct, topValue, topCount := 0, byte(0), 0
		for v, c := range counts {
			if c > 0 {
				distinct++
			}
			if c > topCount {
				topCount, topValue = c, byte(v)
			}
		}
		if topCount >= limit {
			findings = append(findings, PositionFinding{
				Offset:   off,
				Value:    topValue,
				Count:    topCount,
				Share:    float64(topCount) / float64(total),
				Distinct: distinct,
			})
		}
	}
	return findings
}

// overrepresentationThreshold is the smallest count that a uniform byte field
// is unlikely to reach by chance, given the number of samples and the number
// of (offset, value) comparisons the caller is making.
//
// The count of one value at one offset is Binomial(total, 1/256), close enough
// to Poisson with mean total/256. The threshold is the smallest k whose
// upper-tail probability, multiplied by the number of comparisons, stays under
// familyAlpha - so a clean protocol produces a finding roughly once in a
// million runs, and the test does not have to be muted for being flaky.
func overrepresentationThreshold(total, comparisons int) int {
	const familyAlpha = 1e-6
	if comparisons < 1 {
		comparisons = 1
	}
	mean := float64(total) / 256
	if mean <= 0 {
		return 1
	}
	target := familyAlpha / float64(comparisons)

	// Walk the Poisson tail upwards until it is small enough. The loop is
	// bounded by total, and in practice ends within a few dozen steps.
	tail := 1.0 // P(X >= 0)
	term := math.Exp(-mean)
	for k := 0; k <= total; k++ {
		if tail <= target {
			return k
		}
		tail -= term
		if tail < 0 {
			tail = 0
		}
		term *= mean / float64(k+1)
	}
	return total + 1
}

// LengthReport describes the distribution of packet lengths in a corpus.
type LengthReport struct {
	Streams  int
	Distinct int
	Min, Max int
	// TopLength is the single most common length and TopShare its share. A
	// narrow peak here is how an outer layer betrays the inner one: it means
	// the framing of what is carried survives into what is on the wire.
	TopLength int
	TopShare  float64
	// Counts is the histogram, for printing.
	Counts map[int]int
}

func (r LengthReport) String() string {
	return fmt.Sprintf("%d streams, %d distinct lengths in [%d, %d], most common %d in %.1f%%",
		r.Streams, r.Distinct, r.Min, r.Max, r.TopLength, r.TopShare*100)
}

// Lengths builds the length distribution of a corpus.
func Lengths(corpus [][]byte) LengthReport {
	r := LengthReport{Streams: len(corpus), Counts: make(map[int]int)}
	if len(corpus) == 0 {
		return r
	}
	r.Min = len(corpus[0])
	for _, p := range corpus {
		n := len(p)
		r.Counts[n]++
		if n < r.Min {
			r.Min = n
		}
		if n > r.Max {
			r.Max = n
		}
	}
	r.Distinct = len(r.Counts)
	for n, c := range r.Counts {
		if c > r.Counts[r.TopLength] || (c == r.Counts[r.TopLength] && n < r.TopLength) {
			r.TopLength = n
		}
	}
	r.TopShare = float64(r.Counts[r.TopLength]) / float64(len(corpus))
	return r
}

// IntervalReport describes the gaps between frames, which is where a fixed
// keepalive period shows up as a constant.
type IntervalReport struct {
	Samples   int
	TopBucket float64
	TopShare  float64
	Bucket    float64
}

// Intervals buckets gaps (in seconds) and reports the most common bucket. A
// keepalive with a fixed period puts nearly everything in one bucket.
func Intervals(gaps []float64, bucket float64) IntervalReport {
	r := IntervalReport{Samples: len(gaps), Bucket: bucket}
	if len(gaps) == 0 || bucket <= 0 {
		return r
	}
	counts := make(map[int]int)
	for _, g := range gaps {
		counts[int(g/bucket)]++
	}
	topKey, topCount := 0, -1
	for k, c := range counts {
		if c > topCount || (c == topCount && k < topKey) {
			topKey, topCount = k, c
		}
	}
	r.TopBucket = float64(topKey) * bucket
	r.TopShare = float64(topCount) / float64(len(gaps))
	return r
}

// Report is the whole level-1 and level-2 picture for one corpus, in the form
// that goes into a test log or the tool's output.
type Report struct {
	Level1    Level1
	Openings  OpeningReport
	Positions []PositionFinding
	Lengths   LengthReport
	Prefix    int
}

// Analyze runs every corpus-level check. prefix is how many leading bytes of
// each stream the positional check looks at; 64 is the checklist's number.
//
// The positional check runs past each stream's printable opening rather than
// from byte zero. A transport that opens with encoded bytes has a run of them
// in front of its body, and comparing absolute offsets across such a corpus
// measures the alphabet of the opening instead of the body behind it - every
// offset inside the run looks over-represented, and nothing beyond it lines
// up. Aligning on the end of the opening is what an analyst would do, and it
// is the stricter reading: the body is then compared against itself. The
// opening is not thereby excused - Openings checks that its length varies,
// which is the property that keeps the body from having fixed offsets again.
func Analyze(corpus [][]byte, prefix int) Report {
	return Report{
		Level1:    RunLevel1(corpus),
		Openings:  Openings(corpus),
		Positions: PositionalUniformity(alignPastOpening(corpus), prefix),
		Lengths:   Lengths(corpus),
		Prefix:    prefix,
	}
}

func (r Report) String() string {
	var b strings.Builder
	l1 := r.Level1
	fmt.Fprintf(&b, "level 1: %d of %d streams match no exemption (%.1f%%), mean %.3f bits per byte\n",
		l1.Blocked, l1.Streams, l1.BlockedShare()*100, l1.MeanBitsPerByte)

	keys := make([]int, 0, len(l1.ByExemption))
	for e := range l1.ByExemption {
		keys = append(keys, int(e))
	}
	sort.Ints(keys)
	for _, k := range keys {
		e := Exemption(k)
		fmt.Fprintf(&b, "  %-40s %d\n", e, l1.ByExemption[e])
	}

	fmt.Fprintf(&b, "level 2: openings: %s\n", r.Openings)
	fmt.Fprintf(&b, "level 2: lengths: %s\n", r.Lengths)
	if len(r.Positions) == 0 {
		fmt.Fprintf(&b, "level 2: first %d bytes past the opening: no over-represented value\n", r.Prefix)
		return b.String()
	}
	fmt.Fprintf(&b, "level 2: first %d bytes past the opening: %d offsets carry a value more often than chance\n",
		r.Prefix, len(r.Positions))
	for _, f := range r.Positions {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	return b.String()
}
