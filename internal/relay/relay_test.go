package relay

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

// nopCloseDst is the half-close of a test that does not care about it.
func nopCloseDst() {}

func TestAnUnmeteredHalfJustCopies(t *testing.T) {
	dst := &bytes.Buffer{}
	closed := false
	h := &Half{
		Dst:      dst,
		Src:      strings.NewReader("hello"),
		CloseDst: func() { closed = true },
	}
	if err := h.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dst.String() != "hello" {
		t.Errorf("copied %q, want %q", dst.String(), "hello")
	}
	if !closed {
		// CloseDst is what passes the end of the stream on. A half that ends
		// without it leaves the destination waiting for a request that will
		// never come - the failure the half-close counter exists for.
		t.Error("CloseDst did not run")
	}
}

// The counter is what a quota is enforced against, so it has to agree with
// what was actually written, not approximately.
func TestAMeteredHalfCountsEveryByteItWrote(t *testing.T) {
	const size = 300 * 1024
	var counter atomic.Int64
	dst := &bytes.Buffer{}
	h := &Half{
		Dst:      dst,
		Src:      bytes.NewReader(make([]byte, size)),
		Counter:  &counter,
		CloseDst: nopCloseDst,
	}
	if err := h.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := counter.Load(); got != size {
		t.Errorf("counted %d bytes, want %d", got, size)
	}
	if dst.Len() != size {
		t.Errorf("wrote %d bytes, want %d", dst.Len(), size)
	}
}

// The flush boundary is the only moment the account can be asked a question
// whose answer sees the truth, and it is also what bounds the overrun: a
// session cannot run more than FlushThreshold past its quota.
func TestAHalfStopsWithinOneFlushOfTheQuota(t *testing.T) {
	var counter atomic.Int64
	const limit = FlushThreshold

	h := &Half{
		Dst:     io.Discard,
		Src:     bytes.NewReader(make([]byte, 10*FlushThreshold)),
		Counter: &counter,
		Status: func() Status {
			if counter.Load() >= limit {
				return QuotaExceeded
			}
			return Allowed
		},
		Exhaust:  func(Status) bool { return false },
		CloseDst: nopCloseDst,
	}

	if err := h.Run(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Run returned %v, want ErrNotAllowed", err)
	}
	if got := counter.Load(); got < limit || got > limit+FlushThreshold {
		t.Errorf("stopped at %d bytes; want within one flush (%d) of the limit %d",
			got, FlushThreshold, limit)
	}
}

// A half told to drain keeps copying after the account is spent - that is the
// grace period - and is not asked again, because the answer cannot change
// back.
func TestADrainingHalfKeepsCopyingAndIsAskedOnlyOnce(t *testing.T) {
	var counter atomic.Int64
	var asked, exhausted int

	const size = 10 * FlushThreshold
	h := &Half{
		Dst:     io.Discard,
		Src:     bytes.NewReader(make([]byte, size)),
		Counter: &counter,
		Status: func() Status {
			asked++
			return QuotaExceeded
		},
		Exhaust:  func(Status) bool { exhausted++; return true },
		CloseDst: nopCloseDst,
	}

	if err := h.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := counter.Load(); got != size {
		t.Errorf("the drain stopped at %d bytes, want the whole %d", got, size)
	}
	if asked != 1 || exhausted != 1 {
		t.Errorf("status asked %d times and exhaust called %d; want 1 and 1", asked, exhausted)
	}
}

// A half with no counter still asks the account. This is the F01 case: the
// counter for an account that has just been removed is nil, so tying the
// question to the counter silenced it for exactly the account that had to be
// stopped.
func TestAHalfWithoutACounterStillAsksTheAccount(t *testing.T) {
	asked := 0
	h := &Half{
		Dst:      io.Discard,
		Src:      bytes.NewReader(make([]byte, 10*FlushThreshold)),
		Status:   func() Status { asked++; return Expired },
		Exhaust:  func(Status) bool { return false },
		CloseDst: nopCloseDst,
	}
	if err := h.Run(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Run = %v, want ErrNotAllowed", err)
	}
	if asked == 0 {
		t.Error("an unmetered half never asked the account whether it may continue")
	}
}

// The plain copy is for a half that has nothing to do on a flush boundary.
// Every byte still arrives, and nothing is asked because there is nobody to
// ask.
func TestAHalfWithNeitherCounterNorStatusJustCopies(t *testing.T) {
	const size = 3*FlushThreshold + 17
	var dst bytes.Buffer
	closed := false
	h := &Half{
		Dst:      &dst,
		Src:      bytes.NewReader(make([]byte, size)),
		CloseDst: func() { closed = true },
	}
	if err := h.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dst.Len() != size {
		t.Errorf("copied %d bytes, want %d", dst.Len(), size)
	}
	if !closed {
		t.Error("the plain copy did not close the destination's write side")
	}
}

type writeCloser struct {
	io.Writer
	err    error
	closed bool
}

func (w *writeCloser) CloseWrite() error { w.closed = true; return w.err }

func TestHalfCloseReportsWhatTheTransportCouldDo(t *testing.T) {
	t.Run("supported", func(t *testing.T) {
		w := &writeCloser{Writer: io.Discard}
		var got error
		called := false
		HalfClose(w, func(err error) { got, called = err, true })
		if !w.closed || !called || got != nil {
			t.Errorf("closed=%v called=%v err=%v; want true, true, nil", w.closed, called, got)
		}
	})

	t.Run("refused by the transport", func(t *testing.T) {
		want := errors.New("no")
		w := &writeCloser{Writer: io.Discard, err: want}
		var got error
		HalfClose(w, func(err error) { got = err })
		if !errors.Is(got, want) {
			t.Errorf("observed %v, want %v", got, want)
		}
	})

	// The case the counter was added for: a transport with no half-close at
	// all, which used to be silently indistinguishable from a successful one.
	t.Run("unsupported", func(t *testing.T) {
		var got error
		HalfClose(io.Discard, func(err error) { got = err })
		if !errors.Is(got, ErrHalfCloseUnsupported) {
			t.Errorf("observed %v, want ErrHalfCloseUnsupported", got)
		}
	})

	t.Run("nobody listening", func(t *testing.T) {
		// A nil observer is the configured-off case and must not panic.
		HalfClose(io.Discard, nil)
	})
}

// The account's reason has to survive the trip into the session's vocabulary:
// an expired account and a spent quota end the session for different reasons
// and an operator reading the metric needs to tell them apart.
func TestAStatusKeepsItsReasonAsAnAccountState(t *testing.T) {
	for _, tc := range []struct {
		status Status
		want   string
	}{
		{Expired, "expired"},
		{QuotaExceeded, "quota_exceeded"},
		// Allowed never reaches this path - it is asked only when the answer
		// was not Allowed - and the fallback must not invent "expired".
		{Allowed, "quota_exceeded"},
	} {
		if got := tc.status.AccountState().String(); got != tc.want {
			t.Errorf("status %d became %s, want %s", tc.status, got, tc.want)
		}
	}
}

// The package documents a Half as "Dst, Src and the hooks below", and the
// hooks are what a caller adds when it has an account to meter or a stream to
// pass an end to. That smallest configuration has to run, or the description
// is of something the package cannot do (review finding R12).
func TestTheSmallestHalfTheDocumentationDescribesRuns(t *testing.T) {
	t.Run("no hooks at all", func(t *testing.T) {
		var dst bytes.Buffer
		h := &Half{Dst: &dst, Src: strings.NewReader("hello")}
		if err := h.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if dst.String() != "hello" {
			t.Errorf("copied %q, want %q", dst.String(), "hello")
		}
	})

	t.Run("metered, with nowhere to pass the end of the stream", func(t *testing.T) {
		// The long body takes the flush path rather than the plain copy, so
		// both ways out of Run are covered.
		var counter atomic.Int64
		const size = 3*FlushThreshold + 17
		h := &Half{
			Dst:     io.Discard,
			Src:     bytes.NewReader(make([]byte, size)),
			Counter: &counter,
		}
		if err := h.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if counter.Load() != size {
			t.Errorf("counted %d bytes, want %d", counter.Load(), size)
		}
	})

	t.Run("an account that says stop, with nobody to grant a grace", func(t *testing.T) {
		// Without an Exhaust hook the refusal is final: a half that kept
		// copying because nobody answered would be transferring for an
		// account that has just been told it may not.
		h := &Half{
			Dst:    io.Discard,
			Src:    bytes.NewReader(make([]byte, 10*FlushThreshold)),
			Status: func() Status { return QuotaExceeded },
		}
		if err := h.Run(); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("Run = %v, want ErrNotAllowed", err)
		}
	})
}
