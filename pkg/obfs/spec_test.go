package obfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-1 makes docs/veil-spec.md the single source of truth for the
// wire format: both ends are implemented from the document rather than from
// reading each other's code, and a disagreement between the two is a bug in
// one of them.
//
// A specification nobody checks drifts within one release. These tests are
// the check. They do not parse the document as a grammar - they assert that
// every constant the format hangs on appears in it with the value the code
// uses, so changing the code without changing the document fails here.
const specPath = "../../docs/veil-spec.md"

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("the format specification is missing: %v", err)
	}
	return string(b)
}

func TestTheSpecificationStatesTheSizesTheCodeUses(t *testing.T) {
	spec := readSpec(t)

	for _, c := range []struct {
		what  string
		value string
		why   string
	}{
		{"frame overhead", fmt.Sprintf("2 + 1 + 2 + 2 + 16 = %d", frameOverhead),
			"the per-frame cost on the wire"},
		{"minimum ciphertext", fmt.Sprintf("1 + 2 + 2 + 16 = %d", minCiphertext),
			"the length below which a frame cannot come from this format"},
		{"salt size", fmt.Sprintf("**%d байта**", saltSize),
			"the session salt the client sends ahead of its first frame"},
		{"default MTU", fmt.Sprintf("| %d |", DefaultMTU),
			"the default frame size in the parameters table"},
		{"encoded prologue", fmt.Sprintf("%d символа, алфавит", encodedPrologueSize),
			"the length of the encoded opening"},
		{"opening pad", fmt.Sprintf("0..%d символов того же алфавита", openingPadMax),
			"the pad that follows the encoded prologue"},
		{"opening pad derivation", fmt.Sprintf("client opening\", 2)) mod %d", openingPadMax+1),
			"how both ends derive the pad length"},
	} {
		if !strings.Contains(spec, c.value) {
			t.Errorf("%s: the specification does not state %q (%s). "+
				"Change the document before the code, not after it.", c.what, c.value, c.why)
		}
	}
}

func TestTheSpecificationListsEveryFrameKind(t *testing.T) {
	spec := readSpec(t)

	for _, k := range []struct {
		kind frameKind
		name string
	}{
		{kindData, "data"},
		{kindKeepalive, "keepalive"},
		{kindFIN, "FIN"},
		{kindHello, "hello"},
		{kindAdvice, "advice"},
	} {
		row := fmt.Sprintf("`0x%02X` | %s", byte(k.kind), k.name)
		if !strings.Contains(spec, row) {
			t.Errorf("frame kind %s (0x%02X) is missing from the table in section 5.4, "+
				"expected a row starting %q", k.name, byte(k.kind), row)
		}
	}
}

func TestTheSpecificationListsEveryFailureReason(t *testing.T) {
	spec := readSpec(t)

	// Every reason an operator can see in the metric has to be in the table
	// that says what it means; a new one added without a line there is a
	// reason nobody can act on.
	for _, r := range []FailureReason{
		ReasonEOFBeforeFrame,
		ReasonShortFrame,
		ReasonDecryptFail,
		ReasonReplay,
		ReasonBadOpening,
		ReasonUnknownFrameKind,
		ReasonBadControl,
	} {
		if !strings.Contains(spec, "`"+string(r)+"`") {
			t.Errorf("failure reason %q is missing from section 11 of the specification", r)
		}
	}
}

func TestTheSpecificationStatesTheKeyDerivationLabels(t *testing.T) {
	spec := readSpec(t)

	// The labels are the one part of the format two independent
	// implementations cannot guess. They are copied here from deriveSession
	// deliberately: if the labels change, this test fails until both the
	// document and this list follow.
	for _, label := range []string{
		"S5Core/obfs v1 client data",
		"S5Core/obfs v1 server data",
		"S5Core/obfs v1 client length",
		"S5Core/obfs v1 server length",
	} {
		if !strings.Contains(spec, label) {
			t.Errorf("HKDF label %q is missing from section 4.1 of the specification", label)
		}
	}

	// And that the list is complete: the code must not derive under a label
	// the document does not name. Scanning the source for string literals
	// would not catch it any more - veil builds its labels by concatenation -
	// so the check recomputes the keys from the documented labels instead. If
	// the code moved to a label the document does not carry, the keys differ.
	session, err := veil.Derive(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		what      string
		keys      veil.Keys
		dataLabel string
		lenLabel  string
	}{
		{"what a client sends", session.Send, "S5Core/obfs v1 client data", "S5Core/obfs v1 client length"},
		{"what a client reads", session.Recv, "S5Core/obfs v1 server data", "S5Core/obfs v1 server length"},
	} {
		wantData := keyFromSpecLabel(t, psk, secret, d.dataLabel)
		wantLen := keyFromSpecLabel(t, psk, secret, d.lenLabel)
		if !sameAEAD(t, d.keys.Data, wantData) {
			t.Errorf("%s is not encrypted under the label %q the specification names", d.what, d.dataLabel)
		}
		if !sameMask(d.keys.LengthMask, wantLen) {
			t.Errorf("%s is not length-masked under the label %q the specification names", d.what, d.lenLabel)
		}
	}
}

// keyFromSpecLabel runs the derivation the specification describes in section
// 4.1, using nothing from pkg/veil. It is the second implementation the
// document promises is possible.
func keyFromSpecLabel(t *testing.T, psk, secret []byte, label string) []byte {
	t.Helper()
	prk, err := hkdf.Extract(sha256.New, psk, secret)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Expand(sha256.New, prk, label, 32)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sameAEAD reports whether an AEAD holds the given key, by the only thing an
// AEAD exposes: what it produces.
func sameAEAD(t *testing.T, have cipher.AEAD, key []byte) bool {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, have.NonceSize())
	plain := []byte("the specification is the source of truth")
	return bytes.Equal(have.Seal(nil, nonce, plain, nil), want.Seal(nil, nonce, plain, nil))
}

// sameMask reports whether a length mask holds the given key, by the bytes
// it produces. The specification describes the default (AES) mask as the
// head of an AES block over the counter, so that is what it is compared
// against.
func sameMask(have veil.LengthMask, key []byte) bool {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	var in, out [aes.BlockSize]byte
	for counter := range uint64(4) {
		in = [aes.BlockSize]byte{}
		binary.BigEndian.PutUint64(in[8:], counter)
		block.Encrypt(out[:], in[:])
		if have.Mask(counter) != binary.BigEndian.Uint16(out[:2]) {
			return false
		}
	}
	return true
}

// psk and secret are arbitrary: the test compares two derivations of the same
// inputs, so any pair of values that is not all zeroes will do.
var (
	psk    = []byte("0123456789abcdef0123456789abcdef")
	secret = []byte("a prologue that is thirty-two by")
)

// The epoch is the one part of the format that a deployment can get wrong
// without anything failing loudly: too narrow a window and unsynchronised
// clients disappear, too wide and a recorded prologue lives longer than the
// document promises. So the document has to carry the numbers.
func TestTheSpecificationStatesTheEpochNumbers(t *testing.T) {
	spec := readSpec(t)

	for _, c := range []struct {
		what  string
		value string
	}{
		// Spelled as the document spells them, not as bare numbers: "2"
		// appears on every other line of any document, and a check that
		// matches it proves nothing.
		{"the epoch length in seconds", fmt.Sprintf("unix_time / %d", veil.EpochSeconds)},
		{"the MAC label of the clocked scheme", `"S5Core/veil v1 epoch"`},
		{"the accepting window", fmt.Sprintf("по умолчанию **%d**", veil.DefaultEpochWindow)},
		{"the diagnostic window", fmt.Sprintf("по умолчанию %d эпох", veil.DefaultDiagnosticWindow)},
		{"the random half of the prologue", fmt.Sprintf("Random       = %d случайных байта", veil.SaltSize-8)},
	} {
		if !strings.Contains(spec, c.value) {
			t.Errorf("%s is %s in the code and nowhere in section 3.2 of the specification", c.what, c.value)
		}
	}

	// The prologue is still one field of one size, whatever the scheme puts
	// in it. A scheme that needed more would be a format change.
	if got := (&veil.Clocked{}).Size(); got != saltSize {
		t.Errorf("the clocked prologue is %d bytes, the framing reserves %d", got, saltSize)
	}
}

// A second cipher is only useful if the other end can be built from the
// document. So the document has to name both, and name what changes with
// them: nothing about the frame's shape, everything about the two keys.
func TestTheSpecificationStatesTheCiphers(t *testing.T) {
	spec := readSpec(t)

	for _, c := range veil.Ciphers() {
		if !strings.Contains(spec, "| `"+string(c)+"`") {
			t.Errorf("cipher %q has no row in the table in section 5.0 of the specification", c)
		}
	}
	if !strings.Contains(spec, `Cipher  по умолчанию = "`+string(veil.DefaultCipher)+`"`) {
		t.Errorf("the specification does not state that the default cipher is %q", veil.DefaultCipher)
	}
	for _, name := range []string{"AES-256-GCM", "ChaCha20-Poly1305"} {
		if !strings.Contains(spec, name) {
			t.Errorf("the specification does not name %s", name)
		}
	}

	// The claim the whole design rests on: the two are interchangeable
	// because their sizes are. If that stopped being true, the document
	// would be promising something the code does not do.
	for _, c := range veil.Ciphers() {
		session, err := veil.Derive(psk, secret, veil.Context{Cipher: c}, veil.RoleClient)
		if err != nil {
			t.Fatal(err)
		}
		if got := session.Send.Data.NonceSize() + session.Send.Data.Overhead(); got != 12+16 {
			t.Errorf("cipher %q costs %d bytes of nonce and tag, section 5.0 says 12 + 16", c, got)
		}
	}
}

// Section 3.4 is the roster: a prologue that carries who is calling. The
// document states the layout in bytes and the labels in full, and both are
// things a reader would implement from. Here they are checked against what
// the code does, so the two cannot drift apart quietly.
func TestTheSpecificationStatesTheRoster(t *testing.T) {
	spec := readSpec(t)

	for _, claim := range []string{
		"Prologue = Random (16) || Identity (8) || MAC[0:8]",
		`"S5Core/veil v1 user"`,
		`"S5Core/veil v1 identity"`,
		"OBFS_MEMBER_KEY",
		"OBFS_REQUIRE_MEMBER_KEY",
		"tunnel_key",
	} {
		if !strings.Contains(spec, claim) {
			t.Errorf("section 3.4 of the specification does not state %q", claim)
		}
	}

	// The sizes the layout line promises have to be the sizes the code
	// uses, or the line is fiction.
	if veil.SaltSize != 16+8+8 {
		t.Errorf("the prologue is %d bytes, section 3.4 splits it into 16 + 8 + 8", veil.SaltSize)
	}
	if veil.MemberKeySize != 32 {
		t.Errorf("a member key is %d bytes, section 3.4 says 32", veil.MemberKeySize)
	}

	// And the claim that makes the roster worth having, stated in the
	// document as "Secret = Prologue (32) || uint64_BE(Epoch) ||
	// MemberKey": the member's own key is part of the secret, which is why
	// two members with the same PSK cannot read each other's traffic.
	// (That consequence is measured in pkg/veil/roster_test.go; what is
	// checked here is that the line in the document is true.)
	key := make([]byte, veil.MemberKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	client := &veil.Roster{Member: veil.Member{ID: "spec", Key: key}}
	offered, err := client.Offer(psk, make([]byte, veil.SaltSize))
	if err != nil {
		t.Fatal(err)
	}
	if want := veil.SaltSize + 8 + veil.MemberKeySize; len(offered.Secret) != want {
		t.Errorf("the secret is %d bytes, section 3.4 composes it from %d", len(offered.Secret), want)
	}
	if !bytes.HasSuffix(offered.Secret, key) {
		t.Error("the secret does not end with the member key, as section 3.4 says it does")
	}
}
