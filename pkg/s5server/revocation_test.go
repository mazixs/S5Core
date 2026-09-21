package s5server

import (
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// An account has one life cycle, whichever door it came through. These tests
// are the two ends of it against a real tunnel: an account created through the
// SDK raises one under its own key, and an account taken away stops raising
// one at that moment rather than at the next reload.
//
// Findings F01 and R07 of docs/reports/code-quality-audit-2026-09-20.md.

// keyOf reads an account's tunnel key out of the store. A test may do this;
// a caller of the SDK asks Admin.TunnelKey, which costs a permission.
func keyOf(t *testing.T, srv *Server, username string) []byte {
	t.Helper()
	account, ok := srv.userStore.Identity(username)
	if !ok {
		t.Fatalf("the store does not know %q", username)
	}
	if len(account.Key) != veil.MemberKeySize {
		t.Fatalf("%q has a %d-byte tunnel key, want %d", username, len(account.Key), veil.MemberKeySize)
	}
	return account.Key
}

// R07. An account added through the SDK is a member like any other: it gets a
// key of its own, the directory learns it without a reload, and the tunnel
// names it. Before the fix AddUser stored no key at all, so the account was
// invisible to the directory - under OBFS_REQUIRE_MEMBER_KEY it could not
// connect, and without it the account silently shared the anonymous account's
// session secret, which is the one thing member keys exist to prevent.
func TestAnAccountAddedThroughTheSDKIsAMemberAtOnce(t *testing.T) {
	srv, port, _, echo := memberStand(t, true)

	before := srv.members.Len()
	if err := srv.AddUser("carol", "a password carol never sends"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	// The directory, not the store, is what the wire consults: the new
	// account has to be in it before the next reload, not after.
	if after := srv.members.Len(); after != before+1 {
		t.Fatalf("the directory holds %d members after AddUser, want %d", after, before+1)
	}

	tunnel := dialMember(t, port, &veil.Roster{
		Member: veil.Member{ID: "carol", Key: keyOf(t, srv, "carol")},
	})
	// connectAsMember sends no credentials and fails if the server asks for
	// any: reaching the echo is the proof that the tunnel resolved the name.
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("an account added through the SDK could not raise a tunnel: %v", err)
	}
	if err := echoThrough(tunnel, "carol-ping"); err != nil {
		t.Fatalf("the new member's tunnel carries nothing: %v", err)
	}

	// Named, not merely admitted: the bytes land on carol's account.
	_ = tunnel.Close()
	carol := srv.userStore.TrafficCounterFor("carol")
	deadline := time.Now().Add(2 * time.Second)
	for carol.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if carol.Load() == 0 {
		t.Error("the tunnel admitted the new account without accounting its traffic to it")
	}
}

// F01. Removing an account withdraws its key from the directory in the same
// call. Before the fix only ReloadUsers rebuilt the directory, so a removed
// member kept connecting with the key it already had until the next reload -
// which, on a server whose accounts are managed through the SDK, may be
// never.
func TestRemovingAnAccountRevokesItsTunnelKeyAtOnce(t *testing.T) {
	srv, port, key, echo := memberStand(t, true)
	alice := veil.Member{ID: "alice", Key: key}
	before := srv.members.Len()

	live := dialMember(t, port, &veil.Roster{Member: alice})
	if err := connectAsMember(live, echo); err != nil {
		t.Fatalf("a member could not connect before being removed: %v", err)
	}
	if err := echoThrough(live, "still-a-member"); err != nil {
		t.Fatalf("the member's tunnel carries nothing: %v", err)
	}

	if err := srv.RemoveUser("alice"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	// The key is out of the directory, not merely out of the store: a key
	// still in it resolves a prologue, and a prologue that resolves is a
	// session.
	if n := srv.members.Len(); n != before-1 {
		t.Fatalf("the directory holds %d members after a removal, want %d", n, before-1)
	}

	after := dialMember(t, port, &veil.Roster{Member: alice})
	_ = after.SetDeadline(time.Now().Add(2 * time.Second))
	if err := connectAsMember(after, echo); err == nil {
		t.Fatal("a removed member raised a tunnel with the key it used to have")
	}
}

// The same for a promotion: SetRole goes through the store, and the directory
// has to end up agreeing with it. The account keeps its key and keeps
// connecting - the point is that rebuilding the directory does not drop
// members that are still there.
func TestChangingARoleKeepsTheMemberInTheDirectory(t *testing.T) {
	srv, port, key, echo := memberStand(t, true)
	before := srv.members.Len()

	if err := srv.SetRole("alice", "operator"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if n := srv.members.Len(); n != before {
		t.Fatalf("the directory holds %d members after a role change, want %d", n, before)
	}

	tunnel := dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("a member lost its tunnel to a change of role: %v", err)
	}
	if err := echoThrough(tunnel, "still-here"); err != nil {
		t.Fatalf("the promoted member's tunnel carries nothing: %v", err)
	}
}

// F01, second layer. The member directory is a snapshot, so between rebuilds
// it can name an account that may no longer connect; the store is asked at
// connection time for that reason. The removal here goes straight to the
// store, which is what a stale snapshot looks like from the tunnel's side.
//
// Without the check the connection was admitted under NoAuth on the strength
// of the snapshot alone, and the relay then never asked the account anything,
// because an account that is gone has no traffic counter and the question
// used to be tied to the counter.
func TestAStaleDirectoryEntryDoesNotAdmitAGoneAccount(t *testing.T) {
	srv, port, key, echo := memberStand(t, true)
	alice := veil.Member{ID: "alice", Key: key}

	// Straight to the store: the directory keeps the entry it has.
	if err := srv.userStore.RemoveUser("alice"); err != nil {
		t.Fatalf("store.RemoveUser: %v", err)
	}
	if srv.members.Len() == 0 {
		t.Fatal("the directory emptied itself; this test no longer covers a stale entry")
	}

	tunnel := dialMember(t, port, &veil.Roster{Member: alice})
	_ = tunnel.SetDeadline(time.Now().Add(2 * time.Second))
	if err := connectAsMember(tunnel, echo); err == nil {
		t.Fatal("an account the store no longer holds connected on a stale directory entry")
	}
}
