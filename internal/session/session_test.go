package session

import (
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// recorder keeps every transition an observer saw.
type recorder struct {
	mu   sync.Mutex
	seen []Transition
}

func (r *recorder) observe(t Transition) {
	r.mu.Lock()
	r.seen = append(r.seen, t)
	r.mu.Unlock()
}

func (r *recorder) legal(region Region) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, t := range r.seen {
		if t.Region == region && !t.Illegal {
			out = append(out, t.FromName()+">"+t.ToName())
		}
	}
	return out
}

func (r *recorder) illegal() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, t := range r.seen {
		if t.Illegal {
			out = append(out, t.Region.String()+":"+t.FromName()+">"+t.ToName())
		}
	}
	return out
}

func open(t *testing.T, sla SLA, framed bool) (*Session, *recorder) {
	t.Helper()
	rec := &recorder{}
	reg := NewRegistry(rec.observe)
	s := reg.Open("plain", framed, sla)
	t.Cleanup(s.Close)
	return s, rec
}

func TestTheProtocolRegionFollowsItsTable(t *testing.T) {
	// Every state of the region against every target: which moves the
	// table permits. Same-state moves are no-ops and are not listed.
	allowed := map[Protocol][]Protocol{
		Accepted:   {Handshake, Closed},
		Handshake:  {Dialing, Relay, Closed},
		Dialing:    {Relay, Closed},
		Relay:      {HalfClosed, Closed},
		HalfClosed: {Closed},
		Closed:     {},
	}
	all := []Protocol{Accepted, Handshake, Dialing, Relay, HalfClosed, Closed}

	for from, targets := range allowed {
		for _, to := range all {
			if to == from {
				continue
			}
			s := &Session{}
			s.protocol.Store(uint32(from))
			got := s.Enter(to)
			want := slices.Contains(targets, to)
			if got != want {
				t.Errorf("%s -> %s: legal=%v, want %v", from, to, got, want)
			}
			if got && s.Protocol() != to {
				t.Errorf("%s -> %s: state is %s afterwards", from, to, s.Protocol())
			}
			if !got && s.Protocol() != from {
				t.Errorf("%s -> %s refused, but state moved to %s", from, to, s.Protocol())
			}
		}
	}
}

func TestTheFramesRegionDoesNotExistForAnUnframedSession(t *testing.T) {
	s, rec := open(t, SLA{}, false)
	if s.Frames() != Unframed {
		t.Fatalf("frames = %s, want unframed", s.Frames())
	}
	for _, f := range []Frames{AwaitHeader, AwaitBody, Deliver, FrameError} {
		if s.Frame(f) {
			t.Errorf("unframed session accepted %s", f)
		}
	}
	if s.Frames() != Unframed {
		t.Fatalf("frames = %s after refused moves", s.Frames())
	}
	if got := rec.illegal(); len(got) != 4 {
		t.Fatalf("illegal transitions reported: %v, want four", got)
	}
}

func TestTheFramesRegionCyclesAndEndsInAnError(t *testing.T) {
	s, rec := open(t, SLA{}, true)
	if s.Frames() != AwaitHeader {
		t.Fatalf("a framed session starts in %s, want await_header", s.Frames())
	}
	for _, f := range []Frames{AwaitBody, Deliver, AwaitHeader, AwaitBody, AwaitHeader, Deliver} {
		if !s.Frame(f) {
			t.Fatalf("%s -> %s refused", s.Frames(), f)
		}
	}
	if s.Frame(Unframed) {
		t.Fatal("a framed session became unframed")
	}
	if !s.Frame(FrameError) {
		t.Fatal("frame_error refused")
	}
	for _, f := range []Frames{AwaitHeader, AwaitBody, Deliver} {
		if s.Frame(f) {
			t.Errorf("frame_error left for %s", f)
		}
	}
	want := []string{
		"await_header>await_body", "await_body>deliver", "deliver>await_header",
		"await_header>await_body", "await_body>await_header", "await_header>deliver",
		"deliver>frame_error",
	}
	if got := rec.legal(RegionFrames); !slices.Equal(got, want) {
		t.Fatalf("transitions = %v, want %v", got, want)
	}
}

func TestExhaustionDuringARelayDrainsThroughHalfClose(t *testing.T) {
	s, rec := open(t, SLA{Grace: 5 * time.Second}, false)
	for _, p := range []Protocol{Handshake, Dialing, Relay} {
		s.Enter(p)
	}

	if !s.Exhaust(QuotaExceeded) {
		t.Fatal("the first Exhaust did not win")
	}
	if s.Exhaust(QuotaExceeded) {
		t.Fatal("the second Exhaust also claims to have won")
	}
	if s.Account() != Grace || !s.InGrace() {
		t.Fatalf("account = %s, want grace", s.Account())
	}
	if s.Protocol() != HalfClosed {
		t.Fatalf("protocol = %s, want half_closed: the account region did not couple", s.Protocol())
	}
	end, ok := s.GraceDeadline()
	if !ok || time.Until(end) > 5*time.Second || time.Until(end) < 4*time.Second {
		t.Fatalf("grace deadline = %v, %v; want about five seconds out", end, ok)
	}

	s.Close()
	if s.Account() != QuotaExceeded {
		t.Fatalf("account = %s after close, want quota_exceeded", s.Account())
	}
	if s.Protocol() != Closed {
		t.Fatalf("protocol = %s after close", s.Protocol())
	}
	if got := rec.legal(RegionAccount); !slices.Equal(got, []string{"within_quota>grace", "grace>quota_exceeded"}) {
		t.Fatalf("account transitions = %v", got)
	}
	if got := rec.legal(RegionProtocol); !slices.Equal(got, []string{
		"accepted>handshake", "handshake>dialing", "dialing>relay", "relay>half_closed", "half_closed>closed",
	}) {
		t.Fatalf("protocol transitions = %v", got)
	}
	if got := rec.illegal(); len(got) != 0 {
		t.Fatalf("illegal transitions: %v", got)
	}
}

func TestExhaustionRemembersWhyTheDrainBegan(t *testing.T) {
	s, _ := open(t, SLA{Grace: time.Second}, false)
	s.Enter(Handshake)
	s.Enter(Relay)
	s.Exhaust(Expired)
	s.Close()
	if s.Account() != Expired {
		t.Fatalf("account = %s, want expired", s.Account())
	}
}

func TestWithoutAGraceBudgetExhaustionIsImmediate(t *testing.T) {
	s, _ := open(t, SLA{}, false)
	s.Enter(Handshake)
	s.Enter(Relay)
	if !s.Exhaust(QuotaExceeded) {
		t.Fatal("Exhaust did not win")
	}
	if s.Account() != QuotaExceeded {
		t.Fatalf("account = %s, want quota_exceeded", s.Account())
	}
	if s.Protocol() != Relay {
		t.Fatalf("protocol = %s; without grace the caller ends the session, the model does not", s.Protocol())
	}
	if _, ok := s.GraceDeadline(); ok {
		t.Fatal("a grace deadline without grace")
	}
}

func TestExhaustionBeforeTheRelayIsImmediateEvenWithGrace(t *testing.T) {
	// The account ran out while the request was still being read: there is
	// nothing in flight to let through.
	s, _ := open(t, SLA{Grace: time.Minute}, false)
	s.Enter(Handshake)
	s.Exhaust(Expired)
	if s.Account() != Expired {
		t.Fatalf("account = %s, want expired", s.Account())
	}
	if s.Protocol() != Handshake {
		t.Fatalf("protocol = %s, want handshake", s.Protocol())
	}
}

func TestDeadlinesComeFromTheStateTable(t *testing.T) {
	sla := SLA{
		Handshake: 15 * time.Second,
		ReadIdle:  30 * time.Second,
		WriteIdle: 10 * time.Second,
		FrameBody: 3 * time.Second,
		Grace:     5 * time.Second,
	}
	accepted := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	fresh := func(framed bool) *Session {
		s := NewRegistry(nil).Open("plain", framed, sla)
		s.acceptedAt = accepted
		return s
	}

	cases := []struct {
		name  string
		setup func() *Session
		now   time.Time
		read  time.Duration // expected, relative to now; -1 means none
		write time.Duration
	}{
		{
			name:  "accepted: the idle timeout applies, the budget is further away",
			setup: func() *Session { return fresh(false) },
			now:   accepted,
			read:  15 * time.Second, // min(30s idle, 15s budget)
			write: 10 * time.Second,
		},
		{
			name: "handshake: the budget is stricter than the idle timeout",
			setup: func() *Session {
				s := fresh(false)
				s.Enter(Handshake)
				return s
			},
			now:   accepted.Add(12 * time.Second),
			read:  3 * time.Second, // the budget has 3 s left
			write: 3 * time.Second,
		},
		{
			name: "dialing counts against the same budget",
			setup: func() *Session {
				s := fresh(false)
				s.Enter(Handshake)
				s.Enter(Dialing)
				return s
			},
			now:   accepted.Add(14 * time.Second),
			read:  time.Second,
			write: time.Second,
		},
		{
			name: "relay of a stream: idle timeouts only",
			setup: func() *Session {
				s := fresh(false)
				s.Enter(Handshake)
				s.Enter(Relay)
				return s
			},
			now:   accepted.Add(time.Hour),
			read:  30 * time.Second,
			write: 10 * time.Second,
		},
		{
			name: "relay of a tunnel: no deadline at all",
			setup: func() *Session {
				s := fresh(false)
				s.Enter(Handshake)
				s.Become(Tunnel)
				s.Enter(Relay)
				return s
			},
			now:   accepted.Add(time.Hour),
			read:  -1,
			write: -1,
		},
		{
			name: "a tunnel waiting for the rest of a frame is bounded by the frame budget",
			setup: func() *Session {
				s := fresh(true)
				s.Enter(Handshake)
				s.Become(Tunnel)
				s.Enter(Relay)
				s.Frame(AwaitBody)
				return s
			},
			now:   accepted.Add(time.Hour),
			read:  3 * time.Second,
			write: -1, // the frame budget is about what is read
		},
		{
			name: "a stream waiting for the rest of a frame takes the stricter of the two",
			setup: func() *Session {
				s := fresh(true)
				s.Enter(Handshake)
				s.Enter(Relay)
				s.Frame(AwaitBody)
				return s
			},
			now:   accepted.Add(time.Hour),
			read:  3 * time.Second,
			write: 10 * time.Second,
		},
		{
			name: "a frame waiting for its header is idle, not stuck",
			setup: func() *Session {
				s := fresh(true)
				s.Enter(Handshake)
				s.Become(Tunnel)
				s.Enter(Relay)
				s.Frame(AwaitBody)
				s.Frame(Deliver)
				s.Frame(AwaitHeader)
				return s
			},
			now:   accepted.Add(time.Hour),
			read:  -1,
			write: -1,
		},
		{
			name: "closed: nothing is armed",
			setup: func() *Session {
				s := fresh(false)
				s.Enter(Closed)
				return s
			},
			now:   accepted,
			read:  -1,
			write: -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.setup()
			// This table uses a fixed clock for every absolute state start.
			if s.Frames() == AwaitBody {
				s.frameBodyAt.Store(tc.now.UnixNano())
			}
			check := func(what string, got time.Time, ok bool, want time.Duration) {
				if want < 0 {
					if ok {
						t.Errorf("%s deadline = %v, want none", what, got.Sub(tc.now))
					}
					return
				}
				if !ok {
					t.Errorf("%s: no deadline, want %v", what, want)
					return
				}
				if d := got.Sub(tc.now); d != want {
					t.Errorf("%s deadline in %v, want %v", what, d, want)
				}
			}
			r, rok := s.ReadDeadline(tc.now)
			check("read", r, rok, tc.read)
			w, wok := s.WriteDeadline(tc.now)
			check("write", w, wok, tc.write)
		})
	}
}

func TestTheGraceDeadlineBoundsTheDrain(t *testing.T) {
	s, _ := open(t, SLA{ReadIdle: time.Minute, Grace: 5 * time.Second}, false)
	s.Enter(Handshake)
	s.Enter(Relay)
	s.Exhaust(QuotaExceeded)
	began := time.Unix(0, s.graceAt.Load())

	// Well inside the drain the idle timeout is the further bound and the
	// grace end the nearer one.
	now := began.Add(time.Second)
	d, ok := s.ReadDeadline(now)
	if !ok || !d.Equal(began.Add(5*time.Second)) {
		t.Fatalf("read deadline = %v, want the grace end %v", d, began.Add(5*time.Second))
	}
	// A tunnel in grace is bounded too: without this a UDP tunnel of an
	// exhausted account would drain forever.
	s.Become(Tunnel)
	d, ok = s.ReadDeadline(now)
	if !ok || !d.Equal(began.Add(5*time.Second)) {
		t.Fatalf("tunnel read deadline in grace = %v %v", d, ok)
	}
}

func TestTheRegistryCountsSessionsByState(t *testing.T) {
	reg := NewRegistry(nil)
	relay := reg.Open("plain", false, SLA{})
	relay.Enter(Handshake)
	relay.Enter(Relay)
	dialing := []*Session{reg.Open("obfs", true, SLA{}), reg.Open("obfs", true, SLA{})}
	for _, s := range dialing {
		s.Enter(Handshake)
		s.Enter(Dialing)
	}
	dialing[1].Frame(AwaitBody)
	closed := reg.Open("plain", false, SLA{})
	closed.Close()

	if reg.Len() != 3 {
		t.Fatalf("Len = %d, want 3: a closed session left the registry", reg.Len())
	}

	got := map[string]int64{}
	for _, c := range reg.Snapshot() {
		got[c.Transport+"/"+c.Region.String()+"/"+c.StateName()] = c.N
	}
	want := map[string]int64{
		"plain/protocol/relay":       1,
		"plain/account/within_quota": 1,
		"obfs/protocol/dialing":      2,
		"obfs/account/within_quota":  2,
		"obfs/frames/await_header":   1,
		"obfs/frames/await_body":     1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d", k, got[k], n)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected cell %s = %d", k, got[k])
		}
	}
}

func TestANilRegistryStillOpensSessions(t *testing.T) {
	var reg *Registry
	s := reg.Open("plain", false, SLA{Handshake: time.Second})
	if !s.Enter(Handshake) || s.Protocol() != Handshake {
		t.Fatal("a registry-less session does not move")
	}
	s.Close()
	if reg.Len() != 0 || reg.Snapshot() != nil {
		t.Fatal("a nil registry reports sessions")
	}
}

func TestANilSessionIsInert(t *testing.T) {
	var s *Session
	if s.Enter(Relay) || s.Frame(AwaitBody) || s.Exhaust(QuotaExceeded) || s.InGrace() {
		t.Fatal("a nil session moved")
	}
	s.Become(Tunnel)
	s.Close()
	if _, ok := s.ReadDeadline(time.Now()); ok {
		t.Fatal("a nil session has a read deadline")
	}
	if _, ok := s.WriteDeadline(time.Now()); ok {
		t.Fatal("a nil session has a write deadline")
	}
	if s.Protocol() != Closed || s.Frames() != Unframed || s.Account() != WithinQuota || s.Kind() != Stream {
		t.Fatal("a nil session reports states other than the neutral ones")
	}
	if s.Transport() != "" || s.SLA() != (SLA{}) {
		t.Fatal("a nil session has a transport or an SLA")
	}
}

// carrier and wrapper stand in for the connection stack of the server.
type carrier struct {
	net.Conn
	sess *Session
}

func (c *carrier) Session() *Session { return c.sess }

type netConnWrapper struct {
	net.Conn
	inner net.Conn
}

func (w *netConnWrapper) NetConn() net.Conn { return w.inner }

type unwrapWrapper struct {
	net.Conn
	inner net.Conn
}

func (w *unwrapWrapper) Unwrap() net.Conn { return w.inner }

type selfWrapper struct{ net.Conn }

func (w *selfWrapper) Unwrap() net.Conn { return w }

func TestOfFindsTheSessionUnderTheWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	s := NewRegistry(nil).Open("plain", false, SLA{})
	var c net.Conn = &carrier{Conn: a, sess: s}
	c = &netConnWrapper{Conn: a, inner: c}
	c = &unwrapWrapper{Conn: a, inner: c}
	c = &netConnWrapper{Conn: a, inner: c}

	if Of(c) != s {
		t.Fatal("Of did not find the session under three wrappers")
	}
	if Of(a) != nil {
		t.Fatal("a bare pipe has a session")
	}
	if Of(nil) != nil {
		t.Fatal("a nil connection has a session")
	}
	if Of(&selfWrapper{Conn: a}) != nil {
		t.Fatal("a wrapper returning itself was not cut off")
	}
	if Of(&netConnWrapper{Conn: a, inner: nil}) != nil {
		t.Fatal("a wrapper over nil has a session")
	}
}

func TestTransitionsAreSafeUnderContention(t *testing.T) {
	// Many goroutines exhaust and close the same session; exactly one wins
	// the exhaustion, the terminal states are the expected ones, and nothing
	// is reported as illegal.
	s, rec := open(t, SLA{Grace: time.Second}, false)
	s.Enter(Handshake)
	s.Enter(Relay)

	var wins int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Exhaust(QuotaExceeded) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines won the exhaustion, want one", wins)
	}
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()
	if s.Protocol() != Closed || s.Account() != QuotaExceeded {
		t.Fatalf("final states %s/%s", s.Protocol(), s.Account())
	}
	if got := rec.illegal(); len(got) != 0 {
		t.Fatalf("illegal transitions under contention: %v", got)
	}
}

func TestNamesAreStableMetricLabels(t *testing.T) {
	// The names go on the wire of the metrics endpoint; a rename is a
	// dashboard break, so the full set is pinned here.
	if got := []string{Accepted.String(), Handshake.String(), Dialing.String(), Relay.String(), HalfClosed.String(), Closed.String()}; !slices.Equal(got, []string{"accepted", "handshake", "dialing", "relay", "half_closed", "closed"}) {
		t.Fatalf("protocol names = %v", got)
	}
	if got := []string{Unframed.String(), AwaitHeader.String(), AwaitBody.String(), Deliver.String(), FrameError.String()}; !slices.Equal(got, []string{"unframed", "await_header", "await_body", "deliver", "frame_error"}) {
		t.Fatalf("frames names = %v", got)
	}
	if got := []string{WithinQuota.String(), Grace.String(), QuotaExceeded.String(), Expired.String()}; !slices.Equal(got, []string{"within_quota", "grace", "quota_exceeded", "expired"}) {
		t.Fatalf("account names = %v", got)
	}
	if got := []string{RegionProtocol.String(), RegionFrames.String(), RegionAccount.String()}; !slices.Equal(got, []string{"protocol", "frames", "account"}) {
		t.Fatalf("region names = %v", got)
	}
	if Protocol(200).String() != "unknown" || Region(9).StateName(0) != "unknown" {
		t.Fatal("out-of-range values are not spelled unknown")
	}
}
