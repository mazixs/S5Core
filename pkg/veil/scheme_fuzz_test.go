package veil

import (
	"bytes"
	"testing"
	"time"
)

// The prologue is the first thing a server reads from anyone who connects,
// so Accept is the scheme's parser of untrusted input. What the code promises
// about it: a prologue of the wrong size is an error, and every prologue of
// the right size yields a secret - never an error - so that refusing a
// stranger costs the same as refusing a wrong key (docs/design/decoy.md).

// fuzzNow is the middle of an hour, so a skew of whole hours is a skew of as
// many epochs.
var fuzzNow = time.Date(2026, 9, 24, 12, 30, 0, 0, time.UTC)

func fuzzClock() time.Time { return fuzzNow }

var (
	fuzzPSKVeil  = bytes.Repeat([]byte{0x42}, 32)
	fuzzAccepts  = []Context{{}, {Cipher: CipherChaCha}}
	fuzzMembers  = []Member{{ID: "alice", Key: bytes.Repeat([]byte{1}, MemberKeySize)}, {ID: "bob", Key: bytes.Repeat([]byte{2}, MemberKeySize)}}
	fuzzRosterDB = func() *Directory {
		d := &Directory{Now: fuzzClock}
		if err := d.SetMembers(fuzzMembers); err != nil {
			panic(err)
		}
		return d
	}()
)

func fuzzEpoch() int64 { return fuzzNow.Unix() / EpochSeconds }

// FuzzSchemeAccept runs every scheme a server can be configured with over an
// arbitrary prologue and checks:
//   - a wrong size is an error and the right size never is;
//   - the secret is usable: Derive and OpeningPad accept it, the pad is in
//     range, and the same prologue always gives the same answer;
//   - the prologue is neither changed nor aliased by the secret;
//   - a clocked secret is the prologue plus an epoch inside the window, and a
//     roster secret names a member only when it is that member's secret;
//   - the secret a roster server refuses with is none that a client could
//     derive: not the shared account's, not any member's, in any epoch of the
//     window - the property the random stand-in key exists for.
func FuzzSchemeAccept(f *testing.F) {
	for _, s := range []Scheme{
		Symmetric{},
		&Clocked{Now: fuzzClock},
		&Roster{Clocked: Clocked{Now: fuzzClock}, Member: fuzzMembers[0]},
	} {
		p := make([]byte, SaltSize)
		if _, err := s.Offer(fuzzPSKVeil, p); err != nil {
			f.Fatal(err)
		}
		f.Add(p)
	}
	f.Add(make([]byte, SaltSize))
	f.Add(make([]byte, SaltSize+1))
	f.Add([]byte{})

	symmetric := Symmetric{}
	clocked := &Clocked{Now: fuzzClock, Accepts: fuzzAccepts}
	members := &Roster{Clocked: Clocked{Now: fuzzClock, Accepts: fuzzAccepts}, Members: fuzzRosterDB}
	withShared := &Roster{Clocked: Clocked{Now: fuzzClock, Accepts: fuzzAccepts}, Members: fuzzRosterDB, Anonymous: clocked}
	mine := fuzzEpoch()

	f.Fuzz(func(t *testing.T, prologue []byte) {
		orig := append([]byte(nil), prologue...)
		results := map[string]Result{}
		for name, s := range map[string]Scheme{"symmetric": symmetric, "clocked": clocked, "roster": members, "roster+shared": withShared} {
			res, err := s.Accept(fuzzPSKVeil, prologue)
			if len(prologue) != SaltSize {
				if err == nil {
					t.Fatalf("%s accepted a %d-byte prologue", name, len(prologue))
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s refused a prologue with an error: %v", name, err)
			}
			if !bytes.Equal(prologue, orig) {
				t.Fatalf("%s changed the prologue", name)
			}
			if len(res.Secret) == 0 || &res.Secret[0] == &prologue[0] {
				t.Fatalf("%s returned an empty or aliased secret", name)
			}
			if _, err := Derive(fuzzPSKVeil, res.Secret, res.Context, RoleServer); err != nil {
				t.Fatalf("%s: the secret does not derive: %v", name, err)
			}
			if pad, err := OpeningPad(fuzzPSKVeil, res.Secret, res.Context, 20); err != nil || pad < 0 || pad > 20 {
				t.Fatalf("%s: opening pad %d, err=%v", name, pad, err)
			}
			again, _ := s.Accept(fuzzPSKVeil, prologue)
			if !bytes.Equal(again.Secret, res.Secret) || again.Context != res.Context || again.Identity != res.Identity {
				t.Fatalf("%s answered the same prologue twice differently", name)
			}
			results[name] = res
		}
		if len(prologue) != SaltSize {
			return
		}

		if !bytes.Equal(results["symmetric"].Secret, prologue) {
			t.Fatalf("the symmetric secret is not the salt")
		}
		clockedRes := results["clocked"]
		if !inWindow(clockedRes.Secret, prologue, mine) {
			t.Fatalf("the clocked secret %x is not the prologue and an epoch in the window", clockedRes.Secret)
		}

		for _, name := range []string{"roster", "roster+shared"} {
			res := results[name]
			if res.Identity == "" {
				continue
			}
			m, ok := memberNamed(res.Identity)
			if !ok || !isMemberSecret(res.Secret, prologue, m, mine) {
				t.Fatalf("%s named %q with a secret that is not theirs", name, res.Identity)
			}
		}
		if res := results["roster+shared"]; res.Identity == "" && !bytes.Equal(res.Secret, clockedRes.Secret) {
			t.Fatalf("a stranger to the roster did not fall back to the shared account")
		}
		if res := results["roster"]; res.Identity == "" {
			if inWindow(res.Secret, prologue, mine) {
				t.Fatalf("the roster refused with a secret the shared account derives")
			}
			for _, m := range fuzzMembers {
				if isMemberSecret(res.Secret, prologue, m, mine) {
					t.Fatalf("the roster refused with the secret of member %q", m.ID)
				}
			}
		}
	})
}

// inWindow reports whether secret is a clocked secret of prologue for an
// epoch the server's window accepts.
func inWindow(secret, prologue []byte, mine int64) bool {
	for e := mine - DefaultEpochWindow; e <= mine+DefaultEpochWindow; e++ {
		if bytes.Equal(secret, clockedSecret(prologue, e)) {
			return true
		}
	}
	return false
}

func isMemberSecret(secret, prologue []byte, m Member, mine int64) bool {
	for e := mine - DefaultEpochWindow; e <= mine+DefaultEpochWindow; e++ {
		if bytes.Equal(secret, rosterSecret(prologue, e, m.Key)) {
			return true
		}
	}
	return false
}

func memberNamed(id string) (Member, bool) {
	for _, m := range fuzzMembers {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

// serverReadsClient derives both ends' keys and reports whether a frame the
// client seals opens on the server, with the length mask agreeing too.
func serverReadsClient(t *testing.T, offered, accepted Result) bool {
	cs, err := Derive(fuzzPSKVeil, offered.Secret, offered.Context, RoleClient)
	if err != nil {
		t.Fatalf("client Derive: %v", err)
	}
	ss, err := Derive(fuzzPSKVeil, accepted.Secret, accepted.Context, RoleServer)
	if err != nil {
		t.Fatalf("server Derive: %v", err)
	}
	nonce := make([]byte, cs.Send.Data.NonceSize())
	sealed := cs.Send.Data.Seal(nil, nonce, []byte("first frame"), nil)
	_, err = ss.Recv.Data.Open(nil, nonce, sealed, nil)
	return err == nil && cs.Send.LengthMask.Mask(0) == ss.Recv.LengthMask.Mask(0)
}

// FuzzSchemeRoundTrip offers a prologue from a client whose clock is off by a
// whole number of hours and whose context the fuzzer picks, and accepts it on
// a server that takes both ciphers of the current format. The server reads
// the client's frames, under the client's context and with its member's
// name, exactly when the skew is inside the window and the context is one it
// accepts; otherwise its keys do not open them and it names nobody.
func FuzzSchemeRoundTrip(f *testing.F) {
	f.Add(int8(0), uint8(0), uint8(0), false)
	f.Add(int8(2), uint8(1), uint8(1), true)
	f.Add(int8(-3), uint8(0), uint8(0), true)
	f.Add(int8(1), uint8(0), uint8(2), false)
	f.Add(int8(0), uint8(1), uint8(3), true)

	contexts := []Context{{}, {Cipher: CipherChaCha}, {NodeID: "another-node"}, {Version: "v0"}}
	server := &Clocked{Now: fuzzClock, Accepts: fuzzAccepts}
	roster := &Roster{Clocked: Clocked{Now: fuzzClock, Accepts: fuzzAccepts}, Members: fuzzRosterDB}

	f.Fuzz(func(t *testing.T, skew int8, ctxPick, memberPick uint8, asMember bool) {
		clientNow := fuzzNow.Add(time.Duration(skew) * time.Hour)
		ctx := contexts[int(ctxPick)%len(contexts)]
		meets := skew >= -DefaultEpochWindow && skew <= DefaultEpochWindow && int(ctxPick)%len(contexts) < 2

		var client Scheme = &Clocked{Now: func() time.Time { return clientNow }, Context: ctx}
		var accepting Scheme = server
		wantID := ""
		if asMember {
			m := fuzzMembers[int(memberPick)%len(fuzzMembers)]
			client = &Roster{Clocked: Clocked{Now: func() time.Time { return clientNow }, Context: ctx}, Member: m}
			accepting = roster
			wantID = m.ID
		}

		prologue := make([]byte, SaltSize)
		offered, err := client.Offer(fuzzPSKVeil, prologue)
		if err != nil {
			t.Fatalf("Offer: %v", err)
		}
		accepted, err := accepting.Accept(fuzzPSKVeil, prologue)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		// The keys are what has to agree, not the secret alone: a refused
		// context can leave the secret equal and still derive other keys.
		reads := serverReadsClient(t, offered, accepted)
		if meets {
			if !reads || accepted.Context != offered.Context || accepted.Identity != wantID {
				t.Fatalf("skew %dh, context %+v: the ends disagree (reads %v, identity %q, want %q)", skew, ctx, reads, accepted.Identity, wantID)
			}
			return
		}
		if reads || accepted.Identity != "" {
			t.Fatalf("skew %dh, context %+v: accepted as %q, server reads the client: %v", skew, ctx, accepted.Identity, reads)
		}
	})
}
