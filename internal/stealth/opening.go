package stealth

import "fmt"

// A stream may open with a run of printable characters before its encrypted
// body starts. That run is not an accident: it is how a transport buys an
// exemption from the level 1 rule, which blocks a first packet that looks
// fully encrypted and lets a printable one through.
//
// It changes what level 2 has to measure. An analyst looking at such a corpus
// would not compare byte values at absolute offsets - the opening would
// dominate every finding and hide everything behind it. They would align the
// streams on where the opening ends and look at the body. So that is what
// Analyze does, and the opening itself gets a check of its own: its length
// has to vary, or the boundary becomes the constant the positional check was
// looking for.

// openingAlphabet is the character set an encoded opening is drawn from. It
// is base64's, which is what the obfuscated transport uses; a different
// alphabet of printable bytes is still printable, so a run in it is found by
// the same walk.
const openingAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var openingSet = func() (set [256]bool) {
	for i := 0; i < len(openingAlphabet); i++ {
		set[openingAlphabet[i]] = true
	}
	return set
}()

// openingRunFloor is the shortest run treated as an opening rather than as
// coincidence. A uniformly random stream starts with a run of this alphabet
// of length 8 once in 65536 streams, so the floor costs nothing on a corpus
// that has no opening at all and is not reached by chance on one that does.
const openingRunFloor = 8

// OpeningLength is how many bytes a stream's printable opening takes, or 0
// when it has none.
//
// The measurement is what an observer can do without keys: walk the alphabet
// from the first byte. It may overshoot by a byte or two when the encrypted
// body happens to begin inside the alphabet, which is noise, not a leak.
func OpeningLength(p []byte) int {
	n := 0
	for n < len(p) && openingSet[p[n]] {
		n++
	}
	if n < openingRunFloor {
		return 0
	}
	return n
}

// OpeningReport is the distribution of opening lengths over a corpus.
type OpeningReport struct {
	Streams int
	// WithOpening is how many streams have one at all.
	WithOpening int
	Min, Max    int
	// Distinct is how many different lengths appeared, and TopShare is the
	// share of the most common one. A single length across the corpus is a
	// constant boundary: everything behind it sits at a fixed offset again,
	// and the positional check would have found it if the opening were not
	// there to hide it.
	Distinct  int
	TopLength int
	TopShare  float64
}

func (r OpeningReport) String() string {
	if r.WithOpening == 0 {
		return fmt.Sprintf("%d streams, none open with printable characters", r.Streams)
	}
	return fmt.Sprintf("%d of %d streams open with printable characters, %d distinct lengths in [%d, %d], most common %d in %.1f%%",
		r.WithOpening, r.Streams, r.Distinct, r.Min, r.Max, r.TopLength, r.TopShare*100)
}

// Openings measures the printable opening of every stream in a corpus.
func Openings(corpus [][]byte) OpeningReport {
	r := OpeningReport{Streams: len(corpus)}
	counts := make(map[int]int)
	for _, p := range corpus {
		n := OpeningLength(p)
		if n == 0 {
			continue
		}
		if r.WithOpening == 0 || n < r.Min {
			r.Min = n
		}
		if n > r.Max {
			r.Max = n
		}
		r.WithOpening++
		counts[n]++
	}
	r.Distinct = len(counts)
	for n, c := range counts {
		if c > counts[r.TopLength] || (c == counts[r.TopLength] && n < r.TopLength) {
			r.TopLength = n
		}
	}
	if r.WithOpening > 0 {
		r.TopShare = float64(counts[r.TopLength]) / float64(r.WithOpening)
	}
	return r
}

// alignPastOpening returns the corpus with each stream's printable opening
// removed, which is how the positional check sees it.
func alignPastOpening(corpus [][]byte) [][]byte {
	out := make([][]byte, 0, len(corpus))
	for _, p := range corpus {
		out = append(out, p[OpeningLength(p):])
	}
	return out
}
