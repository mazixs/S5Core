// Package veil holds the part of the wire format that decides who may speak:
// the prologue a client puts ahead of its first frame, and the session keys
// both ends derive from it.
//
// It exists as a package of its own because of plan task Ф5-2 and the
// requirement attached to it: the authentication scheme must be replaceable
// without rewriting the rest of the format. Everything above this package -
// framing, padding, frame kinds - works against the Scheme interface and
// knows only how many bytes the prologue takes and how to turn it into a
// secret. Swapping the scheme is then one task rather than one migration.
//
// The scheme in use is the symmetric one, chosen at gate G4 on measured
// grounds: the tunnel already sends payload in its first segment, so a 0-RTT
// key exchange has no round trip left to save, and the choice came down to
// how much new cryptographic code each option costs. See
// docs/gates/g4-first-frame.md and docs/veil-spec.md.
//
// Two symmetric schemes live here. Symmetric is the bare one: a random salt
// and nothing else. Clocked is the one deployments use - the same salt with
// a MAC over a coarse hour, so a recorded prologue stops being accepted once
// the hour window passes (plan task Ф5-3).
package veil

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// Role says which end of the connection this is. The two ends share a secret
// and must not share a counter space, so neither may be inferred.
type Role int

const (
	RoleUnset Role = iota
	RoleClient
	RoleServer
)

// Context is what the keys are bound to besides the secret. Both fields end
// up in the HKDF labels rather than on the wire: an explicit version byte is
// a detectable constant, and a node identifier on the wire would be worse.
//
// Version names the format revision. Two builds that disagree about it derive
// different keys and fail as if the PSK were wrong, which is the intended
// behaviour - a version skew is not something to negotiate in the clear.
type Context struct {
	Version string
	// Cipher is which AEAD and length mask this connection uses. Empty
	// means DefaultCipher. A client picks it from what its processor is
	// good at (PreferredCipher); a server takes what the client picked,
	// because the choice is in the prologue MAC.
	Cipher Cipher
	// NodeID binds the keys to one server. Empty means unbound - a single
	// server, or a fleet that shares one identity. Set it and a prologue
	// minted for node A is not accepted by node B (plan task Ф5-4), which
	// is what makes a local replay history sufficient: there is nothing to
	// share between nodes, because a recording cannot travel.
	NodeID string
}

// normalized fills in what was left implicit, so that two contexts meaning
// the same thing compare equal. A scheme returns normalized contexts: the
// caller derives under what it is given and must not have to guess whether
// an empty version meant the current one.
func (c Context) normalized() Context {
	if c.Version == "" {
		c.Version = DefaultVersion
	}
	if c.Cipher == "" {
		c.Cipher = DefaultCipher
	}
	return c
}

// String is the canonical rendering of a context, and the one that goes into
// the prologue MAC of the clocked scheme. Two contexts that render the same
// are the same context.
func (c Context) String() string {
	version := c.Version
	if version == "" {
		version = DefaultVersion
	}
	s := version
	if c.Cipher != "" && c.Cipher != DefaultCipher {
		// The default cipher is rendered as nothing at all, so that a
		// deployment that never thought about ciphers derives exactly the
		// labels docs/veil-spec.md lists.
		s += " cipher " + string(c.Cipher)
	}
	if c.NodeID != "" {
		s += " node " + c.NodeID
	}
	return s
}

// DefaultVersion is the label version of the format described in
// docs/veil-spec.md.
const DefaultVersion = "v1"

// Keys is what one direction needs: an AEAD for the payload and a block
// cipher for the length mask. The mask runs on a key of its own so that the
// bytes hiding the frame boundary are not the cipher protecting the payload.
type Keys struct {
	Data       cipher.AEAD
	LengthMask LengthMask
}

// Session is the pair of directions as seen from one end.
type Session struct {
	Send Keys
	Recv Keys
}

// Scheme turns a prologue on the wire into a shared secret. It is the
// replaceable half of the first frame.
//
// A client calls Offer to fill the bytes it puts ahead of its first frame and
// gets the secret back. A server reads Size bytes and calls Accept on them.
// Nothing above this interface knows whether those bytes are a random salt, a
// point on a curve, or anything else.
//
// Accept must not report "this prologue is not ours" as an error. A server
// that refuses at the prologue answers a wrong key faster than it answers a
// wrong payload, and an active probe measures that difference (see section
// 3.3 of docs/veil-spec.md). A scheme that does not recognise a prologue
// returns a secret that will not match instead, and the connection dies where
// every other wrong key dies: on the tag of the first frame. An error from
// Accept means the scheme could not run at all - a malformed buffer, not a
// failed authentication.
type Scheme interface {
	// Name identifies the scheme in logs and tests. It is not sent anywhere.
	Name() string
	// Size is how many bytes the prologue occupies on the wire.
	Size() int
	// Offer fills dst (exactly Size bytes) with the prologue a client sends
	// and returns what to derive session keys from. The returned secret
	// aliases nothing in dst that the caller may reuse.
	Offer(psk, dst []byte) (Result, error)
	// Accept recovers what a client derived, from the prologue it sent. It
	// must not be given a slice the caller will reuse.
	Accept(psk, prologue []byte) (Result, error)
}

// Result is what a scheme hands back: the secret the session keys come from,
// and the context they are bound to.
//
// The context is part of the scheme's answer rather than a separate setting
// because a server may accept more than one - during a format migration it
// accepts both the old labels and the new, and only the scheme knows which
// of them the client used. Everything above just derives under what it is
// given (plan task Ф5-4).
type Result struct {
	Secret  []byte
	Context Context
	// Identity is which member the scheme recognised, empty when the scheme
	// has no notion of members. It is the name the rest of the server knows
	// the user by, resolved before the first frame is decrypted, so that a
	// password is no longer what identifies anyone (plan task Ф5-5).
	Identity string
}

// SaltSize is the prologue length of the symmetric scheme.
const SaltSize = 32

// Symmetric is the scheme in use: the client draws a random salt, sends it,
// and both ends derive the session keys from the PSK and that salt. No point
// of a curve reaches the wire, and no new cryptographic code is vendored.
//
// What it does not provide is forward secrecy. The salt is public, so
// whoever learns the PSK can derive the keys of a recorded session. That is a
// known debt with a measured price, recorded in
// docs/gates/g4-first-frame.md rather than hidden here.
type Symmetric struct {
	// Context binds the keys to a format version and a node. It is not in
	// the prologue - the bare scheme has nowhere to put it - so both ends
	// must be configured with the same one or they derive different keys.
	Context Context
}

func (Symmetric) Name() string { return "symmetric" }
func (Symmetric) Size() int    { return SaltSize }

func (s Symmetric) Offer(_, dst []byte) (Result, error) {
	if len(dst) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue buffer is %d bytes, the symmetric scheme needs %d", len(dst), SaltSize)
	}
	if _, err := io.ReadFull(rand.Reader, dst); err != nil {
		return Result{}, fmt.Errorf("veil: failed to draw a session salt: %w", err)
	}
	// The secret is a copy: the caller owns dst and may hand it to the
	// socket, while the secret outlives the write.
	secret := make([]byte, SaltSize)
	copy(secret, dst)
	return Result{Secret: secret, Context: s.Context.normalized()}, nil
}

func (s Symmetric) Accept(_, prologue []byte) (Result, error) {
	if len(prologue) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue is %d bytes, the symmetric scheme needs %d", len(prologue), SaltSize)
	}
	secret := make([]byte, SaltSize)
	copy(secret, prologue)
	return Result{Secret: secret, Context: s.Context.normalized()}, nil
}

// label builds the HKDF context string for one direction and purpose. The
// node identifier is appended only when set, so a deployment that has not
// adopted node binding derives exactly the labels docs/veil-spec.md lists.
func (c Context) label(who, purpose string) string {
	version := c.Version
	if version == "" {
		version = DefaultVersion
	}
	s := "S5Core/obfs " + version + " " + who + " " + purpose
	if c.Cipher != "" && c.Cipher != DefaultCipher {
		s += " cipher " + string(c.Cipher)
	}
	if c.NodeID != "" {
		s += " node " + c.NodeID
	}
	return s
}

// Derive produces both directions' keys from the secret a Scheme recovered.
//
// The PSK is never a key on its own: it is the input keying material, the
// secret is the salt, and every key below is an HKDF output. Two connections
// under one PSK therefore share no key, and the two directions of one
// connection share neither key nor counter space.
func Derive(psk, secret []byte, ctx Context, role Role) (*Session, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("veil: PSK must be 32 bytes, got %d", len(psk))
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("veil: the scheme returned an empty secret")
	}
	if role != RoleClient && role != RoleServer {
		return nil, fmt.Errorf("veil: role must be RoleClient or RoleServer; the two ends share a key and must not share a counter space")
	}

	prk, err := hkdf.Extract(sha256.New, psk, secret)
	if err != nil {
		return nil, fmt.Errorf("veil: key derivation failed: %w", err)
	}

	sendWho, recvWho := "client", "server"
	if role == RoleServer {
		sendWho, recvWho = recvWho, sendWho
	}

	var s Session
	if s.Send, err = deriveDirection(prk, ctx, sendWho); err != nil {
		return nil, err
	}
	if s.Recv, err = deriveDirection(prk, ctx, recvWho); err != nil {
		return nil, err
	}
	return &s, nil
}

func deriveDirection(prk []byte, ctx Context, who string) (Keys, error) {
	dataKey, err := hkdf.Expand(sha256.New, prk, ctx.label(who, "data"), 32)
	if err != nil {
		return Keys{}, fmt.Errorf("veil: key derivation failed: %w", err)
	}
	lenKey, err := hkdf.Expand(sha256.New, prk, ctx.label(who, "length"), 32)
	if err != nil {
		return Keys{}, fmt.Errorf("veil: key derivation failed: %w", err)
	}

	aead, err := newAEAD(ctx.Cipher, dataKey)
	if err != nil {
		return Keys{}, err
	}
	mask, err := newLengthMask(ctx.Cipher, lenKey)
	if err != nil {
		return Keys{}, err
	}
	return Keys{Data: aead, LengthMask: mask}, nil
}
