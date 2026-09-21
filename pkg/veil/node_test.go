package veil

import (
	"bytes"
	"testing"
	"time"
)

// Plan task Ф5-4. Two things that cost nothing now and are impossible later:
// the node a prologue was minted for, and the format version, both inside
// the key derivation rather than on the wire.
//
// The acceptance criteria are stated as tests of behaviour, so these are
// them: a frame accepted by node A is refused by node B; a server that
// carries two labels accepts clients of both versions; a server that carries
// one refuses the old client the way it refuses noise.

func clockAt(base time.Time, ctx Context, accepts ...Context) *Clocked {
	return &Clocked{
		Context: ctx,
		Accepts: accepts,
		Now:     func() time.Time { return base },
	}
}

// meets runs one connection's worth of the scheme and reports whether the
// two ends ended up with the same secret and the same context - which is
// exactly the condition for the connection to live.
func meets(t *testing.T, client, server *Clocked) bool {
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
	return bytes.Equal(offered.Secret, accepted.Secret) && offered.Context == accepted.Context
}

func TestAPrologueMintedForOneNodeIsRefusedByAnother(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	edge := clockAt(base, Context{NodeID: "edge"})
	core := clockAt(base, Context{NodeID: "core"})

	if !meets(t, edge, edge) {
		t.Fatal("a node refused its own client")
	}
	if meets(t, edge, core) {
		t.Error("a prologue minted for one node was accepted by another; a recording travels between nodes")
	}
}

// An unbound node is not the same as a node called "": a deployment that has
// not adopted node binding must keep working, and it must not accidentally
// accept clients configured for a named node.
func TestAnUnboundNodeIsItsOwnIdentity(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	unbound := clockAt(base, Context{})
	named := clockAt(base, Context{NodeID: "edge"})

	if !meets(t, unbound, unbound) {
		t.Error("an unbound client could not reach an unbound server")
	}
	if meets(t, named, unbound) {
		t.Error("a client configured for a named node reached a server that has no node identity")
	}
}

func TestAServerCarryingTwoLabelsAcceptsBoth(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)

	oldClient := clockAt(base, Context{Version: "v1"})
	newClient := clockAt(base, Context{Version: "v2"})
	migrating := clockAt(base, Context{Version: "v2"}, Context{Version: "v2"}, Context{Version: "v1"})

	if !meets(t, newClient, migrating) {
		t.Error("a migrating server refused a client on the new format")
	}
	if !meets(t, oldClient, migrating) {
		t.Error("a migrating server refused a client on the old format")
	}

	// And once the migration is over, the old client is gone - refused with
	// nothing to distinguish it from noise, because the refusal happens the
	// same way for both.
	migrated := clockAt(base, Context{Version: "v2"})
	if meets(t, oldClient, migrated) {
		t.Error("a server that dropped the old label still accepts the old client")
	}
}

// The version defaults, so a Context that names no version is the current
// one. Otherwise every caller would have to repeat it and one of them would
// eventually not.
func TestAnUnnamedVersionIsTheCurrentOne(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	if !meets(t, clockAt(base, Context{}), clockAt(base, Context{Version: DefaultVersion})) {
		t.Errorf("a context with no version does not mean %q", DefaultVersion)
	}
}

// What the extra label costs, stated as the plan states it: one more MAC per
// connection, not one more decryption. The scheme recognises the context
// before deriving anything, so a second label cannot cost a second attempt
// at the frame.
func TestASecondLabelCostsOneMAC(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	psk := testPSK()

	one := clockAt(base, Context{Version: "v2"})
	two := clockAt(base, Context{Version: "v2"}, Context{Version: "v2"}, Context{Version: "v1"})

	wire := make([]byte, SaltSize)
	if _, err := clockAt(base, Context{Version: "v1"}).Offer(psk, wire); err != nil {
		t.Fatal(err)
	}

	// The old client's prologue: the single-label server finds nothing, the
	// two-label server finds it on its second try.
	if _, _, ok := one.search(psk, wire, one.epoch(), one.window()); ok {
		t.Fatal("the single-label server recognised the old format")
	}
	epoch, ctx, ok := two.search(psk, wire, two.epoch(), two.window())
	if !ok {
		t.Fatal("the two-label server did not recognise the old format")
	}
	if ctx.Version != "v1" || epoch != two.epoch() {
		t.Errorf("the server resolved the prologue to %+v at epoch %d, want v1 at its own epoch", ctx, epoch)
	}
}

// The context must not reach the wire in any form. If it did, the node
// identity would become the very fingerprint it is meant to avoid.
func TestTheNodeIdentityIsNotOnTheWire(t *testing.T) {
	base := time.Date(2026, 9, 19, 12, 30, 0, 0, time.UTC)
	psk := testPSK()

	name := "edge-prod-01"
	client := clockAt(base, Context{NodeID: name})
	wire := make([]byte, SaltSize)
	if _, err := client.Offer(psk, wire); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(name)) {
		t.Fatal("the node identity is in the prologue in the clear")
	}

	// Two nodes, same client random: the prologues must differ in the MAC
	// only by being unrelated, not by a recognisable pattern.
	other := clockAt(base, Context{NodeID: "core-prod-01"})
	elsewhere := make([]byte, SaltSize)
	if _, err := other.Offer(psk, elsewhere); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wire[clockedRandomSize:], elsewhere[clockedRandomSize:]) {
		t.Error("two nodes produced the same MAC; the identity is not in the MAC at all")
	}
}
