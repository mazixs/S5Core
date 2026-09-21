package veil

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestUnknownRosterDiagnosticCannotGrowDirectory(t *testing.T) {
	dir := testDirectory(t, testMember(t, "alice"))
	now := time.Now()
	roster := &Roster{Members: dir, Clocked: Clocked{Now: func() time.Time { return now }, OnClockSkew: func(int64) {}}}
	initial := len(dir.epochs)
	for range 10 {
		now = now.Add(time.Second)
		if _, err := roster.Accept(testPSK(), make([]byte, SaltSize)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(dir.epochs); got != initial {
		t.Fatalf("unknown prologues grew epochs %d -> %d", initial, got)
	}
}

func TestDirectoryOwnsKeysAndPreparesHourBoundary(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 59, 0, 0, time.UTC)
	alice := testMember(t, "alice")
	original := append([]byte(nil), alice.Key...)
	dir := &Directory{Now: func() time.Time { return at }}
	if err := dir.SetMembers([]Member{alice}); err != nil {
		t.Fatal(err)
	}
	alice.Key[0] ^= 0xff
	// At the next hour a client at the positive edge of the acceptance
	// window must still be found before the background refresh runs.
	epoch := at.Unix()/EpochSeconds + int64(DefaultEpochWindow) + 1
	member, ok := dir.lookup(epoch, memberTag(original, epoch))
	if !ok || !bytes.Equal(member.Key, original) {
		t.Fatal("key alias or unprepared hour boundary")
	}
}

func TestDirectoryRefreshCannotResurrectRevokedMembers(t *testing.T) {
	alice := testMember(t, "alice")
	bob := testMember(t, "bob")
	dir := testDirectory(t, alice)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				dir.Refresh()
			}
		})
	}
	if err := dir.SetMembers([]Member{bob}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	dir.mu.RLock()
	defer dir.mu.RUnlock()
	for epoch, table := range dir.epochs {
		if _, ok := table[memberTag(alice.Key, epoch)]; ok {
			t.Fatal("revoked member resurrected")
		}
		if _, ok := table[memberTag(bob.Key, epoch)]; !ok {
			t.Fatal("new member lost")
		}
	}
}
