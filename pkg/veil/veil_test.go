package veil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/mazixs/S5Core/internal/stealth"
)

func testPSK() []byte { return bytes.Repeat([]byte("K"), 32) }

// seal is a small helper: what one direction's AEAD produces for a fixed
// plaintext and nonce. Two keys are the same key exactly when these match.
func seal(k Keys) []byte {
	var nonce [12]byte
	return k.Data.Seal(nil, nonce[:], []byte("probe"), nil)
}

// mask is the same idea for the length mask: the first few bytes it
// produces. Two masks are the same mask exactly when these match.
func mask(k Keys) []byte {
	out := make([]byte, 0, 8)
	for counter := range uint64(4) {
		out = binary.BigEndian.AppendUint16(out, k.LengthMask.Mask(counter))
	}
	return out
}

func derive(t *testing.T, psk, secret []byte, ctx Context, role Role) *Session {
	t.Helper()
	s, err := Derive(psk, secret, ctx, role)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return s
}

// Plan task Ф5-2 states the acceptance criterion for the symmetric option as
// "the session key is not derived from the PSK alone". This is that check:
// the same secret, the same PSK and yet a different connection must not
// produce the same keystream.
func TestTheSessionKeyIsNotDerivedFromThePSKAlone(t *testing.T) {
	psk := testPSK()
	var scheme Symmetric

	first := make([]byte, scheme.Size())
	secret1, err := scheme.Offer(psk, first)
	if err != nil {
		t.Fatal(err)
	}
	second := make([]byte, scheme.Size())
	secret2, err := scheme.Offer(psk, second)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(secret1.Secret, secret2.Secret) {
		t.Fatal("two connections drew the same salt")
	}

	a := derive(t, psk, secret1.Secret, Context{}, RoleClient)
	b := derive(t, psk, secret2.Secret, Context{}, RoleClient)

	if bytes.Equal(seal(a.Send), seal(b.Send)) {
		t.Error("two connections under one PSK derived the same data key")
	}
	if bytes.Equal(mask(a.Send), mask(b.Send)) {
		t.Error("two connections under one PSK derived the same length mask")
	}
}

func TestTheTwoDirectionsShareNoKey(t *testing.T) {
	s := derive(t, testPSK(), []byte("salt-for-both-directions-0000000"), Context{}, RoleClient)

	if bytes.Equal(seal(s.Send), seal(s.Recv)) {
		t.Error("the two directions derived the same data key")
	}
	if bytes.Equal(mask(s.Send), mask(s.Recv)) {
		t.Error("the two directions derived the same length mask")
	}
	if bytes.Equal(seal(s.Send), mask(s.Send)) {
		t.Error("the data key and the length mask of one direction are the same")
	}
}

// The property the two ends need from each other: what one seals with, the
// other opens with.
func TestTheEndsDeriveMirroredKeys(t *testing.T) {
	psk := testPSK()
	secret := []byte("a shared salt, thirty-two bytes!")

	client := derive(t, psk, secret, Context{}, RoleClient)
	server := derive(t, psk, secret, Context{}, RoleServer)

	if !bytes.Equal(seal(client.Send), seal(server.Recv)) {
		t.Error("the server does not read with the key the client writes with")
	}
	if !bytes.Equal(seal(server.Send), seal(client.Recv)) {
		t.Error("the client does not read with the key the server writes with")
	}
}

// Plan task Ф5-4 puts the format version and the node identifier into the
// derivation context rather than on the wire. The property that makes that
// work is here: a different context is a different key, so a frame produced
// under one is rejected under another exactly as a wrong PSK would be.
func TestTheContextChangesTheKeys(t *testing.T) {
	psk := testPSK()
	secret := []byte("a shared salt, thirty-two bytes!")

	base := derive(t, psk, secret, Context{}, RoleClient)

	for _, ctx := range []Context{
		{Version: "v2"},
		{NodeID: "ams-1"},
		{Version: "v2", NodeID: "ams-1"},
	} {
		other := derive(t, psk, secret, ctx, RoleClient)
		if bytes.Equal(seal(base.Send), seal(other.Send)) {
			t.Errorf("context %+v derives the same key as the default one", ctx)
		}
	}

	// And the default context is exactly the v1 one, so adopting this package
	// changes no bytes for a deployment that has not set either field.
	explicit := derive(t, psk, secret, Context{Version: DefaultVersion}, RoleClient)
	if !bytes.Equal(seal(base.Send), seal(explicit.Send)) {
		t.Error("the empty context and the explicit v1 context disagree")
	}
}

// The labels are the one part two independent implementations cannot guess,
// so they are pinned here against the strings docs/veil-spec.md publishes.
func TestTheLabelsAreTheOnesTheSpecificationPublishes(t *testing.T) {
	ctx := Context{}
	for _, c := range []struct{ who, purpose, want string }{
		{"client", "data", "S5Core/obfs v1 client data"},
		{"server", "data", "S5Core/obfs v1 server data"},
		{"client", "length", "S5Core/obfs v1 client length"},
		{"server", "length", "S5Core/obfs v1 server length"},
	} {
		if got := ctx.label(c.who, c.purpose); got != c.want {
			t.Errorf("label(%q, %q) = %q, the specification says %q", c.who, c.purpose, got, c.want)
		}
	}
}

func TestDeriveRefusesWhatItCannotUse(t *testing.T) {
	secret := []byte("a shared salt, thirty-two bytes!")
	for _, c := range []struct {
		name   string
		psk    []byte
		secret []byte
		role   Role
	}{
		{"short PSK", bytes.Repeat([]byte("k"), 31), secret, RoleClient},
		{"empty secret", testPSK(), nil, RoleClient},
		{"no role", testPSK(), secret, RoleUnset},
	} {
		if _, err := Derive(c.psk, c.secret, Context{}, c.role); err == nil {
			t.Errorf("%s: Derive returned no error", c.name)
		}
	}
}

// The level-2 check from internal/stealth, applied to the prologue alone: a
// thousand of them must show no byte value over-represented at any offset.
// The whole first packet is checked in pkg/obfs; this narrows the same check
// to the part this package owns, so a scheme that leaks structure is caught
// here rather than in someone else's test.
func TestAThousandProloguesShowNoStructure(t *testing.T) {
	psk := testPSK()
	var scheme Symmetric

	corpus := make([][]byte, 1000)
	for i := range corpus {
		p := make([]byte, scheme.Size())
		if _, err := scheme.Offer(psk, p); err != nil {
			t.Fatal(err)
		}
		corpus[i] = p
	}

	findings := stealth.PositionalUniformity(corpus, scheme.Size())
	for _, f := range findings {
		t.Errorf("the prologue has structure at offset %d: %s", f.Offset, f)
	}

	lengths := stealth.Lengths(corpus)
	if lengths.Distinct != 1 {
		t.Errorf("the prologue is a fixed-size field, got %d distinct lengths: %s", lengths.Distinct, lengths)
	}
}

// fixedScheme stands in for a future scheme with a different prologue - a
// curve point, say. It exists to prove the property plan task Ф5-2 demands:
// the authentication scheme is replaceable without touching anything above
// it, so this one works through the same interface at a different size.
type fixedScheme struct{ size int }

func (f fixedScheme) Name() string { return "fixed" }
func (f fixedScheme) Size() int    { return f.size }

func (f fixedScheme) Offer(psk, dst []byte) (Result, error) {
	if len(dst) != f.size {
		return Result{}, fmt.Errorf("prologue buffer is %d bytes, want %d", len(dst), f.size)
	}
	if _, err := io.ReadFull(rand.Reader, dst); err != nil {
		return Result{}, err
	}
	return f.Accept(psk, dst)
}

func (f fixedScheme) Accept(psk, prologue []byte) (Result, error) {
	if len(prologue) != f.size {
		return Result{}, fmt.Errorf("prologue is %d bytes, want %d", len(prologue), f.size)
	}
	secret := make([]byte, 0, f.size+len(psk))
	secret = append(secret, prologue...)
	secret = append(secret, psk...)
	return Result{Secret: secret}, nil
}

func TestAnySchemeWorksThroughTheSameInterface(t *testing.T) {
	psk := testPSK()

	for _, scheme := range []Scheme{Symmetric{}, fixedScheme{size: 48}, fixedScheme{size: 16}} {
		t.Run(fmt.Sprintf("%s/%d", scheme.Name(), scheme.Size()), func(t *testing.T) {
			wire := make([]byte, scheme.Size())
			clientSecret, err := scheme.Offer(psk, wire)
			if err != nil {
				t.Fatalf("Offer: %v", err)
			}

			// What the server sees is the bytes, nothing else.
			serverSecret, err := scheme.Accept(psk, wire)
			if err != nil {
				t.Fatalf("Secret: %v", err)
			}
			if !bytes.Equal(clientSecret.Secret, serverSecret.Secret) {
				t.Fatal("the two ends recovered different secrets from the same prologue")
			}
			if clientSecret.Context != serverSecret.Context {
				t.Fatal("the two ends recovered different contexts from the same prologue")
			}

			client := derive(t, psk, clientSecret.Secret, clientSecret.Context, RoleClient)
			server := derive(t, psk, serverSecret.Secret, serverSecret.Context, RoleServer)
			if !bytes.Equal(seal(client.Send), seal(server.Recv)) {
				t.Error("the derived keys do not mirror")
			}
		})
	}
}

func TestASchemeRefusesAPrologueOfTheWrongSize(t *testing.T) {
	var scheme Symmetric
	if _, err := scheme.Offer(testPSK(), make([]byte, SaltSize-1)); err == nil {
		t.Error("Offer accepted a short buffer")
	}
	if _, err := scheme.Accept(testPSK(), make([]byte, SaltSize+1)); err == nil {
		t.Error("Secret accepted an oversized prologue")
	}
}
