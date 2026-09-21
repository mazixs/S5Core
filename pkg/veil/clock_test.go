package veil

import (
	"bytes"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

// Plan task Ф5-3. The acceptance criterion is stated in clock skew, not in
// epochs: a client 45 minutes out and a client 2 hours out both work; a
// client 25 hours out is refused and the operator can see why.

// atTime builds a pair of schemes standing at two different wall clocks:
// what the client thinks the time is, and what the server thinks.
func atTime(clientSkew time.Duration) (client, server *Clocked, skew *int64) {
	// A fixed instant well inside an hour, so that a skew of minutes does
	// not accidentally cross a boundary and make the test measure the
	// boundary instead of the skew.
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	reported := new(int64)
	*reported = -1

	client = &Clocked{Now: func() time.Time { return base.Add(clientSkew) }}
	server = &Clocked{
		Now:         func() time.Time { return base },
		OnClockSkew: func(epochs int64) { *reported = epochs },
	}
	return client, server, reported
}

// agree reports whether the two ends derived the same secret, which is the
// only thing that decides whether the connection lives.
func agree(t *testing.T, client, server *Clocked) bool {
	t.Helper()
	psk := testPSK()
	wire := make([]byte, SaltSize)
	offered, err := client.Offer(psk, wire)
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	accepted, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return bytes.Equal(offered.Secret, accepted.Secret)
}

func TestAClockThatIsHoursOutStillConnects(t *testing.T) {
	for _, skew := range []time.Duration{
		0,
		45 * time.Minute,
		-45 * time.Minute,
		2 * time.Hour,
		-2 * time.Hour,
	} {
		client, server, _ := atTime(skew)
		if !agree(t, client, server) {
			t.Errorf("a client %v out of step was refused; the window is meant to tolerate hours", skew)
		}
	}
}

func TestAClockThatIsADayOutIsRefusedAndNamed(t *testing.T) {
	client, server, reported := atTime(25 * time.Hour)
	if agree(t, client, server) {
		t.Fatal("a client 25 hours out was accepted; the epoch window is not doing anything")
	}
	if *reported != 25 {
		t.Errorf("the server reported a skew of %d epochs, want 25 - an operator cannot tell a broken clock from a scanner", *reported)
	}
}

// The boundary is the case a wall clock cannot be trusted to reproduce, so
// it is driven by hand: the client is in one hour, the server in the next,
// with no skew between them beyond the boundary itself.
func TestTheHourBoundaryIsNotACliff(t *testing.T) {
	boundary := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)
	psk := testPSK()

	client := &Clocked{Now: func() time.Time { return boundary.Add(-time.Millisecond) }}
	server := &Clocked{Now: func() time.Time { return boundary }}

	if client.epoch() == server.epoch() {
		t.Fatal("the test is not standing on a boundary")
	}

	wire := make([]byte, SaltSize)
	offered, err := client.Offer(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(offered.Secret, accepted.Secret) {
		t.Error("a connection opened a millisecond before the hour was refused a millisecond after it")
	}
}

// What the hour buys: a prologue recorded today is not accepted tomorrow,
// without the server keeping any record of it.
func TestARecordedPrologueExpires(t *testing.T) {
	psk := testPSK()
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	client := &Clocked{Now: func() time.Time { return base }}
	wire := make([]byte, SaltSize)
	offered, err := client.Offer(psk, wire)
	if err != nil {
		t.Fatal(err)
	}

	// Same server, same PSK, no replay history at all - only a later clock.
	later := &Clocked{Now: func() time.Time { return base.Add(24 * time.Hour) }}
	accepted, err := later.Accept(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(offered.Secret, accepted.Secret) {
		t.Error("a prologue recorded a day earlier still derives the same keys")
	}
}

// A prologue the scheme does not recognise must come back as a secret that
// will not match, not as an error. An error would let a server refuse at the
// prologue, which is measurably faster than refusing at the first frame.
func TestAnUnrecognisedPrologueIsNotAnError(t *testing.T) {
	server := &Clocked{Now: time.Now}
	junk := bytes.Repeat([]byte{0xAB}, SaltSize)

	got, err := server.Accept(testPSK(), junk)
	if err != nil {
		t.Fatalf("Accept refused a junk prologue with an error: %v", err)
	}
	if len(got.Secret) == 0 {
		t.Fatal("Accept returned no secret for a junk prologue")
	}
}

// The diagnostic search is rate-limited, because it is the one path an
// unauthenticated peer could otherwise make expensive on demand.
func TestTheDiagnosticSearchIsRateLimited(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	psk := testPSK()

	calls := 0
	server := &Clocked{
		Now:         func() time.Time { return base },
		OnClockSkew: func(int64) { calls++ },
	}
	skewed := &Clocked{Now: func() time.Time { return base.Add(25 * time.Hour) }}

	for range 5 {
		wire := make([]byte, SaltSize)
		if _, err := skewed.Offer(psk, wire); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Accept(psk, wire); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("the server ran %d diagnostic searches for five connections in the same instant, want 1", calls)
	}
}

// Whatever the hour does to the keys, it must not show on the wire: the
// prologue has to stay indistinguishable from the random bytes Symmetric
// sends, or the MAC becomes the fingerprint.
func TestAClockedPrologueLooksLikeRandomBytes(t *testing.T) {
	psk := testPSK()
	scheme := NewClocked()

	const n = 1000
	corpus := make([][]byte, n)
	for i := range corpus {
		p := make([]byte, SaltSize)
		if _, err := scheme.Offer(psk, p); err != nil {
			t.Fatal(err)
		}
		corpus[i] = p
	}

	for _, f := range stealth.PositionalUniformity(corpus, scheme.Size()) {
		t.Errorf("the clocked prologue has structure at offset %d: %s - a MAC that repeats is a fingerprint", f.Offset, f)
	}
}

// Two ends that disagree about the window still interoperate when the clocks
// agree: the window is a server-side tolerance, not a negotiated parameter.
func TestTheWindowIsTheServersOwnBusiness(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	client := &Clocked{Now: func() time.Time { return base }, Window: 7}
	server := &Clocked{Now: func() time.Time { return base }, Window: 1}
	if !agree(t, client, server) {
		t.Error("two ends with different windows and the same clock failed to agree")
	}
}
