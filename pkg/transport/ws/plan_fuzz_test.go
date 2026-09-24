package ws

import (
	"math/rand"
	"slices"
	"testing"
)

// FuzzShaperPlan draws cut plans for any band the configuration lets through
// - WS_MIN_FRAME and WS_MAX_FRAME on either end, and the frame band a server
// may push in TRANSPORT_ADVICE (1..65535, min <= max) - and holds the plan to
// what shaped.go and the review findings say it is:
//   - the pieces add up to the write, and none is empty or negative (R10:
//     ShapedConn.Write slices the write by them);
//   - no bytes, no frames; a write too small to cut is one frame, any other
//     is at least two, so the inner frame never reaches the wire whole;
//   - a write that is cut has no piece over the maximum (R09); one too small
//     to cut is the documented exception, bounded by itself;
//   - with a band that has room for two minimum pieces, no piece is below
//     minPiece;
//   - at most maxExtraCuts more pieces than the band requires;
//   - the plan is a function of the seed.
func FuzzShaperPlan(f *testing.F) {
	f.Add(uint16(DefaultMinFrame), uint16(DefaultMaxFrame), uint32(22752), int64(1))
	f.Add(uint16(DefaultMinFrame), uint16(DefaultMaxFrame), uint32(1422), int64(2))
	f.Add(uint16(64), uint16(128), uint32(129), int64(3))
	f.Add(uint16(4096), uint16(8192), uint32(16000), int64(4))
	f.Add(uint16(0), uint16(0), uint32(65536), int64(5))
	f.Add(uint16(65535), uint16(65535), uint32(1<<17-1), int64(6))
	f.Add(uint16(64), uint16(64), uint32(191), int64(7))
	f.Add(uint16(1), uint16(65535), uint32(128), int64(8))
	f.Add(uint16(1), uint16(1), uint32(0), int64(9))

	f.Fuzz(func(t *testing.T, minFrame, maxFrame uint16, size uint32, seed int64) {
		n := int(size % (1 << 17))
		shaped := NewShapedConn(nil, int(minFrame), int(maxFrame), 0)
		shaped.rng = rand.New(rand.NewSource(seed))
		plan := slices.Clone(shaped.plan(n))
		shaped.rng = rand.New(rand.NewSource(seed))
		if again := shaped.plan(n); !slices.Equal(plan, again) {
			t.Fatalf("band %d-%d, n=%d: one seed gave %v and %v", shaped.minFrame, shaped.maxFrame, n, plan, again)
		}

		sum := 0
		for _, piece := range plan {
			if piece <= 0 {
				t.Fatalf("band %d-%d, n=%d: plan %v has a piece of %d bytes", shaped.minFrame, shaped.maxFrame, n, plan, piece)
			}
			sum += piece
		}
		if sum != n {
			t.Fatalf("band %d-%d, n=%d: plan %v sums to %d", shaped.minFrame, shaped.maxFrame, n, plan, sum)
		}
		for _, piece := range plan {
			if n > max(shaped.maxFrame, 2*minPiece) && piece > shaped.maxFrame {
				t.Fatalf("band %d-%d, n=%d: piece %d is over the maximum", shaped.minFrame, shaped.maxFrame, n, piece)
			}
			if shaped.maxFrame >= 2*minPiece && n > 2*minPiece && piece < minPiece {
				t.Fatalf("band %d-%d, n=%d: piece %d is under %d", shaped.minFrame, shaped.maxFrame, n, piece, minPiece)
			}
		}

		switch {
		case n == 0:
			if len(plan) != 0 {
				t.Fatalf("an empty write was planned as %v", plan)
			}
		case n <= 2*minPiece:
			if len(plan) != 1 {
				t.Fatalf("n=%d is too small to cut and was planned as %v", n, plan)
			}
		default:
			if len(plan) < 2 {
				t.Fatalf("band %d-%d, n=%d went out as one frame", shaped.minFrame, shaped.maxFrame, n)
			}
			need := max(2, (n+shaped.maxFrame-1)/shaped.maxFrame)
			if len(plan) > need+maxExtraCuts {
				t.Fatalf("band %d-%d, n=%d: %d pieces, the band needs %d", shaped.minFrame, shaped.maxFrame, n, len(plan), need)
			}
		}
	})
}
