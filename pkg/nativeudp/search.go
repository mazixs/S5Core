package nativeudp

// The search for the limit of the path (docs/veil-spec.md, 10.7).
const (
	// The control probe of a round: short, so that only a lost packet goes
	// unanswered.
	controlLow, controlHigh = 48, 112
	// The first round probes the top of the range and one size in each of
	// firstBands bands below it, the next ones one size in each of
	// nextBands bands between what came back and what did not.
	firstBands, nextBands = 5, 3
	topSpread             = 8
	// A search ends once hi-lo is this close, or after searchRounds rounds
	// that decided, or after searchRetries in a row that did not.
	searchClose   = 17
	searchRounds  = 3
	searchRetries = 3
)

// Search finds the longest datagram the path carries both ways, in rounds of
// probes. It holds no clock: the caller sends a round, passes it the answers
// and ends the round when they are due.
type Search struct {
	lo, hi    int // lo came back, hi did not
	decided   int
	undecided int
	sizes     []int // of the round in flight, the control last
	answered  []bool
	control   int
	draw      func(n int) int
	sent      int
}

// NewSearch starts a search. draw returns a number in [0, n).
func NewSearch(draw func(n int) int) *Search {
	return &Search{lo: BaseWire, hi: MaxWire + 1, draw: draw}
}

// Round draws the sizes of the next round, the control last. Sizes vary
// within their bands: a probe of one constant size would itself be a shape.
func (s *Search) Round() []int {
	s.sizes = s.sizes[:0]
	top, bands := s.hi, nextBands
	if s.decided == 0 {
		top, bands = MaxWire-s.draw(topSpread+1), firstBands
		s.sizes = append(s.sizes, top)
	}
	// One size in each band of lo+1 .. top-1.
	width := top - s.lo - 1
	for i := range bands {
		from, to := s.lo+1+i*width/bands, s.lo+1+(i+1)*width/bands
		if to > from {
			s.sizes = append(s.sizes, from+s.draw(to-from))
		}
	}
	control := controlLow + s.draw(controlHigh-controlLow+1)
	if control == s.control {
		control = controlLow + (control-controlLow+1)%(controlHigh-controlLow+1)
	}
	s.control = control
	s.sizes = append(s.sizes, control)
	s.answered = append(s.answered[:0], make([]bool, len(s.sizes))...)
	s.sent += len(s.sizes)
	return s.sizes
}

// Answered records an answer of the round by its size. It reports whether
// it was the control's, and whether every probe of the round has its answer.
func (s *Search) Answered(size int) (control, all bool) {
	all = true
	for i, v := range s.sizes {
		if v == size && !s.answered[i] {
			s.answered[i] = true
			control = i == len(s.sizes)-1
		}
		all = all && s.answered[i]
	}
	return control, all && len(s.sizes) > 0
}

// End closes the round and reports whether the search is over. A round whose
// control went unanswered decides nothing: the path lost a packet, and what
// it says of the sizes is not known.
func (s *Search) End() bool {
	if len(s.sizes) == 0 {
		return false
	}
	sizes, answered := s.sizes[:len(s.sizes)-1], s.answered
	control := answered[len(sizes)]
	s.sizes = s.sizes[:0]
	if !control {
		s.undecided++
		return s.undecided >= searchRetries
	}
	s.undecided = 0
	s.decided++
	for i, v := range sizes {
		if answered[i] {
			s.lo = max(s.lo, v)
		}
	}
	// A size below lo that went unanswered was lost, not refused.
	for i, v := range sizes {
		if !answered[i] && v > s.lo {
			s.hi = min(s.hi, v)
		}
	}
	return s.decided >= searchRounds || s.hi-s.lo <= searchClose
}

// Limit is the longest size that came back so far.
func (s *Search) Limit() int { return s.lo }

// Sent is how many probes the search sent.
func (s *Search) Sent() int { return s.sent }
