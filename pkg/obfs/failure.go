package obfs

import (
	"errors"
	"fmt"
)

// FailureReason classifies why an obfuscated frame could not be read.
//
// The classification exists to answer one operational question that a single
// error counter cannot: is this a tampered frame, a recorded connection being
// replayed, a frame that is malformed on its face, or an ordinary disconnect?
// They look identical on the wire and require different reactions, so they are
// counted apart.
//
// There used to be a fifth reason, "oversize", for a declared frame length
// beyond anything the protocol produces. It went away with the frame header:
// the length is now two bytes masked with a key derived from the PSK, so it
// can never exceed 65535 and a peer that does not hold the key cannot produce
// a length that means anything. Such a peer no longer announces itself with an
// absurd number - it simply waits for a frame that never completes, which is
// what a scanner looks like, and that is the point. Since task Ф5-6 the other
// refusals wait too: a server that has not authenticated a connection drains
// it instead of closing it, so the two cases end at the same moment (see
// Config.RefuseLinger and docs/design/decoy.md). See
// docs/design/observability-policy.md: the reason is the only label - the
// source address is deliberately absent, because it would be
// both a privacy leak and an unbounded label.
type FailureReason string

const (
	// ReasonDecryptFail - the AEAD tag did not verify. A wrong PSK and random
	// probe data are indistinguishable here, by design.
	ReasonDecryptFail FailureReason = "decrypt_fail"
	// ReasonReplay - the frame decrypted, but its nonce was seen before.
	ReasonReplay FailureReason = "replay"
	// ReasonShortFrame - the frame is too small to contain a nonce, or the
	// decrypted plaintext is too short to be a valid payload record.
	ReasonShortFrame FailureReason = "short_frame"
	// ReasonEOFBeforeFrame - the peer went away before a complete frame
	// arrived. This is the ordinary-disconnect bucket and is expected to be
	// the largest one; it is counted so that the others stay meaningful.
	ReasonEOFBeforeFrame FailureReason = "eof_before_frame"
	// ReasonUnknownFrameKind - the frame authenticated, so it came from a peer
	// holding the PSK, and declared a kind this build does not know. It means
	// a version skew between the two ends, not an attack, and it is counted
	// apart because the reaction is a deployment one.
	ReasonUnknownFrameKind FailureReason = "unknown_frame_kind"
	// ReasonBadOpening - the opening in front of the first frame was read,
	// but no session came out of it: the scheme refused the prologue, or the
	// derivation of its keys or of its pad failed. It is apart from
	// decrypt_fail because no frame was involved, and apart from short_frame
	// because the bytes were all there (review finding R08).
	ReasonBadOpening FailureReason = "bad_opening"
	// ReasonBadControl - a hello or advice frame authenticated, but its
	// payload does not parse as the TLV sequence this build knows (plan task
	// Ф5-7). Like an unknown kind, it comes from a peer holding the PSK and
	// speaking a different encoding; unlike a field of unknown type, which
	// is skipped, a payload that cannot be walked at all is not guessed at.
	ReasonBadControl FailureReason = "bad_control_frame"
)

// FrameError reports a failed frame read together with its classification and
// the number of bytes received on the connection before the failure. The byte
// count separates "connected and said nothing" from "sent a plausible amount
// of data that did not decrypt" - the shape of a probe.
type FrameError struct {
	Reason FailureReason
	// BytesBefore is the number of bytes read from the underlying connection
	// before this failure, across the whole connection lifetime.
	BytesBefore int64
	// Err is the underlying cause, if any.
	Err error
}

func (e *FrameError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("obfs: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("obfs: %s", e.Reason)
}

func (e *FrameError) Unwrap() error { return e.Err }

// ReasonOf extracts the failure classification from an error returned by Read.
// It reports ok=false for errors that did not originate in the frame layer.
func ReasonOf(err error) (FailureReason, bool) {
	var fe *FrameError
	if errors.As(err, &fe) {
		return fe.Reason, true
	}
	return "", false
}

// FailureObserver is notified of every frame-level failure. It is called from
// the reading goroutine of the connection, so it must not block.
type FailureObserver func(*FrameError)
