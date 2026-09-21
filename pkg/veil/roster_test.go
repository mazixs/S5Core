package veil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

func testMember(t testing.TB, id string) Member {
	t.Helper()
	key := make([]byte, MemberKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return Member{ID: id, Key: key}
}

func testDirectory(t testing.TB, members ...Member) *Directory {
	t.Helper()
	d, err := NewDirectory(members)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// offer runs a client's half and returns the prologue it would send.
func offer(t *testing.T, s Scheme, psk []byte) ([]byte, Result) {
	t.Helper()
	wire := make([]byte, s.Size())
	res, err := s.Offer(psk, wire)
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	return wire, res
}

func TestAMemberIsRecognisedBeforeTheFirstFrame(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	server := &Roster{Members: testDirectory(t, alice, testMember(t, "bob"))}

	wire, offered := offer(t, &Roster{Member: alice}, psk)
	accepted, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	if accepted.Identity != "alice" {
		t.Errorf("the server resolved %q, want %q", accepted.Identity, "alice")
	}
	if !bytes.Equal(offered.Secret, accepted.Secret) {
		t.Error("the two ends derived different secrets")
	}

	client := derive(t, psk, offered.Secret, offered.Context, RoleClient)
	srv := derive(t, psk, accepted.Secret, accepted.Context, RoleServer)
	if !bytes.Equal(seal(client.Send), seal(srv.Recv)) {
		t.Error("the derived keys do not mirror")
	}
}

// Members share the deployment's PSK and must still not share keys: one
// member reading another's traffic is the failure this whole scheme exists
// to prevent.
func TestTwoMembersDeriveDifferentKeys(t *testing.T) {
	psk := testPSK()
	alice, bob := testMember(t, "alice"), testMember(t, "bob")
	server := &Roster{Members: testDirectory(t, alice, bob)}

	wireA, _ := offer(t, &Roster{Member: alice}, psk)
	wireB, _ := offer(t, &Roster{Member: bob}, psk)

	a, err := server.Accept(psk, wireA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := server.Accept(psk, wireB)
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity == b.Identity {
		t.Fatalf("both connections resolved to %q", a.Identity)
	}

	sessionA := derive(t, psk, a.Secret, a.Context, RoleServer)
	sessionB := derive(t, psk, b.Secret, b.Context, RoleServer)
	if bytes.Equal(seal(sessionA.Send), seal(sessionB.Send)) {
		t.Error("two members derived the same session key")
	}
}

// An unknown member must be refused the way noise is refused: no error out
// of Accept, a secret that cannot match, and the failure landing on the tag
// of the first frame.
func TestAnUnknownMemberIsRefusedLikeNoise(t *testing.T) {
	psk := testPSK()
	server := &Roster{Members: testDirectory(t, testMember(t, "alice"))}

	wire, offered := offer(t, &Roster{Member: testMember(t, "mallory")}, psk)
	accepted, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatalf("Accept refused at the prologue, which is a timing oracle: %v", err)
	}
	if accepted.Identity != "" {
		t.Errorf("the server resolved an unknown member as %q", accepted.Identity)
	}
	if bytes.Equal(offered.Secret, accepted.Secret) {
		t.Fatal("an unknown member derived a secret the server agrees with")
	}
}

// Stealing the identity field is not stealing the account: the MAC is under
// the member's own key.
func TestACopiedIdentityIsNotAnIdentity(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	server := &Roster{Members: testDirectory(t, alice)}

	stolen, _ := offer(t, &Roster{Member: alice}, psk)
	// Mallory replays Alice's identity field in a prologue of her own,
	// under a key that is not Alice's.
	forged, _ := offer(t, &Roster{Member: testMember(t, "mallory")}, psk)
	copy(forged[rosterRandomSize:rosterRandomSize+rosterIdentitySize],
		stolen[rosterRandomSize:rosterRandomSize+rosterIdentitySize])

	accepted, err := server.Accept(psk, forged)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Identity != "" {
		t.Errorf("a forged prologue was accepted as %q", accepted.Identity)
	}
}

// The identity field must not repeat: a member who put the same eight bytes
// on the wire twice would be trivially trackable across connections, which
// is worse than the password this replaces.
func TestOneMemberLooksDifferentEveryConnection(t *testing.T) {
	const samples = 1000
	psk := testPSK()
	alice := testMember(t, "alice")
	client := &Roster{Member: alice}

	corpus := make([][]byte, samples)
	seen := make(map[string]int, samples)
	for i := range corpus {
		wire := make([]byte, SaltSize)
		if _, err := client.Offer(psk, wire); err != nil {
			t.Fatal(err)
		}
		field := string(wire[rosterRandomSize : rosterRandomSize+rosterIdentitySize])
		if first, dup := seen[field]; dup {
			t.Fatalf("connections %d and %d put the same identity bytes on the wire", first, i)
		}
		seen[field] = i
		corpus[i] = wire
	}

	for _, f := range stealth.PositionalUniformity(corpus, SaltSize) {
		t.Errorf("one member's prologues have structure at offset %d: %s", f.Offset, f)
	}
}

// Revocation has to bite now, not at the next epoch: an account is closed
// when it is closed.
func TestARevokedMemberStopsResolvingAtOnce(t *testing.T) {
	psk := testPSK()
	alice, bob := testMember(t, "alice"), testMember(t, "bob")
	dir := testDirectory(t, alice, bob)
	server := &Roster{Members: dir}

	wire, _ := offer(t, &Roster{Member: bob}, psk)
	if got, _ := server.Accept(psk, wire); got.Identity != "bob" {
		t.Fatalf("before revocation the server resolved %q", got.Identity)
	}

	if err := dir.SetMembers([]Member{alice}); err != nil {
		t.Fatal(err)
	}
	if got, _ := server.Accept(psk, wire); got.Identity != "" {
		t.Errorf("a revoked member still resolves as %q", got.Identity)
	}
}

// The clock window is Clocked's, and a member must keep working across it.
func TestAMemberWithASkewedClockIsStillRecognised(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	for _, skew := range []time.Duration{-2 * time.Hour, -45 * time.Minute, 0, 45 * time.Minute, 2 * time.Hour} {
		t.Run(skew.String(), func(t *testing.T) {
			clientNow := base.Add(skew)
			client := &Roster{Clocked: Clocked{Now: func() time.Time { return clientNow }}, Member: alice}
			dir := testDirectory(t, alice)
			dir.Now = func() time.Time { return base }
			dir.Refresh()
			server := &Roster{Clocked: Clocked{Now: func() time.Time { return base }}, Members: dir}

			wire, offered := offer(t, client, psk)
			accepted, err := server.Accept(psk, wire)
			if err != nil {
				t.Fatal(err)
			}
			if accepted.Identity != "alice" {
				t.Fatalf("a client %v out was not recognised", skew)
			}
			if !bytes.Equal(offered.Secret, accepted.Secret) {
				t.Error("the two ends derived different secrets")
			}
		})
	}
}

func TestAMemberFromLastYearIsNotRecognised(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	stale := base.Add(-30 * 24 * time.Hour)

	client := &Roster{Clocked: Clocked{Now: func() time.Time { return stale }}, Member: alice}
	dir := testDirectory(t, alice)
	dir.Now = func() time.Time { return base }
	dir.Refresh()
	server := &Roster{Clocked: Clocked{Now: func() time.Time { return base }}, Members: dir}

	wire, _ := offer(t, client, psk)
	got, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != "" {
		t.Errorf("a month-old prologue resolved as %q", got.Identity)
	}
}

// A directory whose background loop has not caught up must still answer
// correctly - a member's connection is not allowed to depend on a ticker.
func TestALookupBuildsAnEpochTheRefreshHasNotReached(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	at := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	dir := testDirectory(t, alice)
	dir.Now = func() time.Time { return at }
	dir.Refresh()

	// Both ends move a day ahead; nothing refreshes the directory.
	later := at.Add(24 * time.Hour)
	client := &Roster{Clocked: Clocked{Now: func() time.Time { return later }}, Member: alice}
	server := &Roster{Clocked: Clocked{Now: func() time.Time { return later }}, Members: dir}

	wire, _ := offer(t, client, psk)
	got, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != "alice" {
		t.Error("a member was refused because the directory had not been refreshed")
	}
}

func TestADirectoryRefusesAMemberWithoutAProperKey(t *testing.T) {
	if _, err := NewDirectory([]Member{{ID: "alice", Key: []byte("short")}}); err == nil {
		t.Error("a directory accepted a member with a 5-byte key")
	}
	if _, err := (&Roster{Member: Member{ID: "alice"}}).Offer(testPSK(), make([]byte, SaltSize)); err == nil {
		t.Error("a client offered a prologue with no member key")
	}
}

func TestADirectoryOfDistinctMembersHasNoCollisions(t *testing.T) {
	members := make([]Member, 2000)
	for i := range members {
		members[i] = testMember(t, fmt.Sprintf("user-%d", i))
	}
	dir := testDirectory(t, members...)
	if clashes := dir.Collisions(); len(clashes) != 0 {
		t.Errorf("identity tags collide: %v", clashes)
	}
	if dir.Len() != len(members) {
		t.Errorf("the directory holds %d members, want %d", dir.Len(), len(members))
	}
}

// rosterStand builds a directory of n members and a prologue from one of
// them, so a measurement times resolution and nothing else.
func rosterStand(tb testing.TB, n int) (*Roster, []byte, []byte) {
	tb.Helper()
	psk := testPSK()
	members := make([]Member, n)
	for i := range members {
		members[i] = testMember(tb, fmt.Sprintf("user-%d", i))
	}
	dir, err := NewDirectory(members)
	if err != nil {
		tb.Fatal(err)
	}
	server := &Roster{Members: dir}

	// The member in the middle of the list: an implementation that walked
	// the members would be caught by it, and one that happened to check the
	// first or the last would not.
	client := &Roster{Member: members[n/2]}
	wire := make([]byte, SaltSize)
	if _, err := client.Offer(psk, wire); err != nil {
		tb.Fatal(err)
	}
	return server, psk, wire
}

// The acceptance criterion of plan task Ф5-5: "поиск пользователя не
// зависит от их числа". Stated as a test rather than only as a benchmark,
// because a benchmark nobody runs is not a guarantee.
//
// The bound is deliberately loose. A constant-time lookup still slows down
// a little as the table outgrows the caches, and that is real; an
// implementation that walked the members would be four thousand times
// slower at this size, not four.
func TestResolvingAMemberDoesNotDependOnHowManyThereAre(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement")
	}

	const (
		few  = 8
		many = 32768
	)

	measure := func(n int) time.Duration {
		server, psk, wire := rosterStand(t, n)
		result := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				if _, err := server.Accept(psk, wire); err != nil {
					b.Fatal(err)
				}
			}
		})
		return time.Duration(result.NsPerOp())
	}

	small, large := measure(few), measure(many)
	if small <= 0 {
		t.Fatalf("the measurement produced nothing: %v", small)
	}
	if ratio := float64(large) / float64(small); ratio > 4 {
		t.Errorf("resolving one of %d members takes %v against %v for one of %d (%.1fx): "+
			"the lookup is not constant in the number of members", many, large, small, few, ratio)
	} else {
		t.Logf("%d members: %v, %d members: %v (%.2fx)", few, small, many, large, ratio)
	}
}

// BenchmarkRosterAccept is the same measurement, reported. See
// docs/benchmarks/ciphers.md for the numbers this produced.
func BenchmarkRosterAccept(b *testing.B) {
	for _, n := range []int{8, 1024, 32768, 262144} {
		b.Run(fmt.Sprintf("members=%d", n), func(b *testing.B) {
			server, psk, wire := rosterStand(b, n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := server.Accept(psk, wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkClockedAccept is the baseline the roster is measured against:
// the same prologue without an identity in it. The difference between the
// two is what resolving a member costs.
func BenchmarkClockedAccept(b *testing.B) {
	psk := testPSK()
	client := NewClocked()
	wire := make([]byte, SaltSize)
	if _, err := client.Offer(psk, wire); err != nil {
		b.Fatal(err)
	}
	server := NewClocked()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := server.Accept(psk, wire); err != nil {
			b.Fatal(err)
		}
	}
}

// And the other side of the trade: what the background rebuild costs, which
// is the work that was moved off the connection path to make Accept flat.
func BenchmarkDirectoryRefresh(b *testing.B) {
	for _, n := range []int{1024, 32768} {
		b.Run(fmt.Sprintf("members=%d", n), func(b *testing.B) {
			members := make([]Member, n)
			for i := range members {
				members[i] = testMember(b, fmt.Sprintf("user-%d", i))
			}
			dir, err := NewDirectory(members)
			if err != nil {
				b.Fatal(err)
			}
			epoch := int64(0)
			dir.Now = func() time.Time {
				epoch++
				return time.Unix(epoch*EpochSeconds, 0)
			}
			b.ReportAllocs()
			for b.Loop() {
				dir.Refresh()
			}
		})
	}
}

// A deployment does not move every client to a key of its own on one
// evening. A server with a fallback must take both: the members it knows
// and the clients that still share the deployment's account.
func TestAServerTakesMembersAndTheSharedAccountAtOnce(t *testing.T) {
	psk := testPSK()
	alice := testMember(t, "alice")
	server := &Roster{Members: testDirectory(t, alice), Anonymous: NewClocked()}

	t.Run("member", func(t *testing.T) {
		wire, offered := offer(t, &Roster{Member: alice}, psk)
		got, err := server.Accept(psk, wire)
		if err != nil {
			t.Fatal(err)
		}
		if got.Identity != "alice" {
			t.Errorf("the server resolved %q, want alice", got.Identity)
		}
		if !bytes.Equal(offered.Secret, got.Secret) {
			t.Error("the two ends derived different secrets")
		}
	})

	t.Run("shared account", func(t *testing.T) {
		wire, offered := offer(t, NewClocked(), psk)
		got, err := server.Accept(psk, wire)
		if err != nil {
			t.Fatal(err)
		}
		if got.Identity != "" {
			t.Errorf("a client of the shared account was resolved as %q", got.Identity)
		}
		if !bytes.Equal(offered.Secret, got.Secret) {
			t.Error("a client of the shared account derived a different secret")
		}
	})

	t.Run("neither", func(t *testing.T) {
		wrong := bytes.Repeat([]byte("x"), 32)
		wire, offered := offer(t, NewClocked(), wrong)
		got, err := server.Accept(psk, wire)
		if err != nil {
			t.Fatalf("Accept refused at the prologue, which is a timing oracle: %v", err)
		}
		// The secrets may well agree here - the clocked secret is the
		// prologue and the hour, both of which a wrong-PSK client gets
		// right. What must differ is the keys, because the PSK is what
		// they are derived from.
		theirs := derive(t, wrong, offered.Secret, offered.Context, RoleClient)
		ours := derive(t, psk, got.Secret, got.Context, RoleServer)
		if bytes.Equal(seal(theirs.Send), seal(ours.Recv)) {
			t.Fatal("a client with the wrong PSK derived keys the server agrees with")
		}
	})
}

// Without a fallback, the shared account is not an account: a server told
// about members takes members only.
func TestWithoutAFallbackOnlyMembersAreAccepted(t *testing.T) {
	psk := testPSK()
	server := &Roster{Members: testDirectory(t, testMember(t, "alice"))}

	wire, offered := offer(t, NewClocked(), psk)
	got, err := server.Accept(psk, wire)
	if err != nil {
		t.Fatal(err)
	}
	theirs := derive(t, psk, offered.Secret, offered.Context, RoleClient)
	ours := derive(t, psk, got.Secret, got.Context, RoleServer)
	if bytes.Equal(seal(theirs.Send), seal(ours.Recv)) {
		t.Error("a client with no member key was accepted by a server that has a roster")
	}
}
