package ws

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
	"time"
)

// ShapedConn decides where one write is cut into WebSocket frames. Under TLS
// each frame becomes its own record, so these lengths are what an observer
// actually sees.
//
// Plan task Ф4-7. What stood here before had a fast path: a write no larger
// than maxFrame went out unchanged. With the default band (512-4096) and an
// obfuscated frame of 1400-1700 bytes, that path took every single write, so
// shaping never happened and the outer frame boundary reproduced the inner one
// exactly. That is worse than no shaping at all: a bare obfuscated stream says
// only "some encrypted protocol", while a WebSocket stream whose frames are
// all 1400-1700 bytes says "a tunnel with a 1400-byte MTU inside". The nesting
// identified the protocol more precisely than the naked stream would have.
//
// The shape is now set by constraints rather than by a captured browser
// profile, which would age badly and would have to be captured per site:
//
//   - every write is cut at least twice, so no frame is ever a copy of the
//     frame inside it;
//   - the number of cuts varies, so the lengths of one inner frame spread over
//     a range instead of landing on n/2;
//   - piece sizes are drawn around the mean with a normal jitter, not
//     uniformly - a flat distribution is itself unusual and separates out once
//     an observer has collected enough frames;
//   - the cut count leans towards fewer, larger frames, which keeps the header
//     and syscall cost down.
//
// What this cannot do is add bytes: the layer carries a byte stream, so a
// frame can only be split, never padded. A write smaller than two minimum
// pieces therefore goes out as it is. Closing that last gap needs cover
// traffic, which is Ф4-8, or padding inside the obfuscation format.
type ShapedConn struct {
	*Conn
	minFrame  int
	maxFrame  int
	maxJitter time.Duration
	rng       *rand.Rand
	writeMu   sync.Mutex
	sizes     []int // reusable cut plan, held under writeMu
}

// minPiece is the smallest frame the shaper will produce deliberately. Below
// it the header overhead stops being worth the disguise.
const minPiece = 64

// maxExtraCuts bounds how much finer a write may be cut than the configured
// band requires. Without it a large write could be chopped into hundreds of
// minimum-sized frames, which costs bandwidth and looks like nothing.
const maxExtraCuts = 3

// The default band. It belongs to the shaper rather than to whoever configures
// it, because the numbers only mean anything against the cut rules above: the
// lower edge has to leave room to cut an obfuscated frame into pieces that are
// not halves of it, which is why it is well below half the MTU.
const (
	DefaultMinFrame = 256
	DefaultMaxFrame = 4096
)

// NewShapedConn creates a traffic-shaped wrapper. minFrame and maxFrame bound
// the frame sizes the shaper aims for; a write smaller than that is not padded
// up to it. maxJitter adds a random delay (0-maxJitter) before a frame with
// 10% probability.
func NewShapedConn(c *Conn, minFrame, maxFrame int, maxJitter time.Duration) *ShapedConn {
	if minFrame <= 0 {
		minFrame = 256
	}
	if maxFrame < minFrame {
		maxFrame = minFrame * 4
	}
	return &ShapedConn{
		Conn:      c,
		minFrame:  minFrame,
		maxFrame:  maxFrame,
		maxJitter: maxJitter,
		// Seeded from crypto/rand: where the cuts fall must not be predictable
		// from the time the connection was made.
		rng:   rand.New(rand.NewSource(seed())),
		sizes: make([]int, 0, 16),
	}
}

func seed() int64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// Write sends b as several WebSocket frames whose lengths come from the cut
// plan, not from b.
//
// Each frame is written on its own, and that is deliberate: under TLS one
// write becomes one record, so frames batched into a single write would arrive
// as a single record of the original length and there would be nothing left to
// hide. The cost is one syscall per frame - a write of one obfuscated frame
// takes about 11 µs instead of 1.9 µs here - and it is the cost of the
// disguise, not an oversight. See docs/benchmarks/frame-shaping.md for the
// measurements.
func (c *ShapedConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for _, size := range c.plan(len(b)) {
		if c.maxJitter > 0 && c.rng.Float32() < 0.1 {
			if err := c.waitWriteDelay(time.Duration(c.rng.Int63n(int64(c.maxJitter)))); err != nil {
				return total, err
			}
		}
		n, err := c.Conn.Write(b[total : total+size])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// plan returns the frame sizes a write of n bytes is cut into. The sizes
// always sum to n: this layer never adds a byte.
func (c *ShapedConn) plan(n int) []int {
	c.sizes = c.sizes[:0]
	if n == 0 {
		// No bytes, no frames. The contract of io.Writer allows an empty
		// write, and this used to answer one with a plan of [0], which is a
		// zero-length binary WebSocket frame: a shape nothing else on this
		// connection produces, at a position an observer can find - the very
		// thing the shaper exists to prevent (review finding R10). Nothing
		// reaches this today, because pkg/obfs never writes an empty frame,
		// which is why it is a defect of the contract and not of the wire.
		return c.sizes
	}
	if n <= 2*minPiece {
		return append(c.sizes, n)
	}

	k := c.cutCount(n)
	base := n / k
	sigma := float64(base) / 8

	rest := n
	for i := 0; i < k-1; i++ {
		left := k - i - 1
		size := base + int(math.Round(c.rng.NormFloat64()*sigma))
		// The draw is around the mean, and the mean sits near the maximum
		// whenever the cut count lands on its floor - so half the draws used
		// to come out above maxFrame and go on the wire that way (review
		// finding R09). The bound is applied here, ahead of floor, because
		// floor is what keeps the pieces summing to n: it can never ask for
		// more than maxFrame anyway, since the cut count is chosen so that
		// what is left fits in the frames that are left.
		//
		// Not to maxFrame exactly. Clamping a normal draw to its bound puts
		// every draw above the bound on one single length, and that is a
		// shape of its own: with the default band a clamp made 4096 the most
		// common length in the corpus at 4.3%, against 1.7% before the bound
		// existed at all, close enough to the 5% the histogram test allows to
		// be a defect waiting for a different payload size. Landing anywhere
		// in the top sixteenth spreads the same mass over a band instead of a
		// line. It costs nothing: bytes taken off this piece go to the pieces
		// after it, which is what floor and ceil below are for.
		if size > c.maxFrame {
			size = c.maxFrame - c.rng.Intn(c.maxFrame/16+1)
		}
		// Whatever the draw, the pieces still have to add up: leave the
		// frames after this one at least their minimum and at most their
		// maximum, or the tail would have to break one bound or the other.
		if floor := rest - left*c.maxFrame; size < floor {
			size = floor
		}
		if ceil := rest - left*minPiece; size > ceil {
			size = ceil
		}
		if size < minPiece {
			size = minPiece
		}
		c.sizes = append(c.sizes, size)
		rest -= size
	}
	return append(c.sizes, rest)
}

// cutCount picks how many frames a write becomes. The floor of two is the
// point of the task: one frame per write is how the inner frame length used to
// reach the wire unchanged.
func (c *ShapedConn) cutCount(n int) int {
	lo := (n + c.maxFrame - 1) / c.maxFrame
	if lo < 2 {
		lo = 2
	}
	hi := n / c.minFrame
	if hi > lo+maxExtraCuts {
		hi = lo + maxExtraCuts
	}
	if limit := n / minPiece; hi > limit {
		hi = limit
	}
	if hi < lo {
		hi = lo
	}
	if lo > hi {
		lo = hi
	}
	if hi == lo {
		return lo
	}

	// Biased towards the low end: fewer and larger frames cost less overhead,
	// and it is the spread that breaks the correspondence with the inner
	// frame, not the average.
	u := c.rng.Float64()
	k := lo + int(u*u*float64(hi-lo+1))
	if k > hi {
		k = hi
	}
	return k
}
