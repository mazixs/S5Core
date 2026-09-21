package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

// FailureKind is a bounded, address-free classification. The original error
// remains available through Unwrap, but must not be copied into public logs.
type FailureKind string

const (
	FailureTimeout  FailureKind = "timeout"
	FailureClosed   FailureKind = "peer_closed"
	FailureCanceled FailureKind = "canceled"
	FailureAuth     FailureKind = "auth_rejected"
	FailureProtocol FailureKind = "protocol_invalid"
	FailurePolicy   FailureKind = "policy_rejected"
	FailureNetwork  FailureKind = "network"
	FailureInternal FailureKind = "internal"
)

// ConnError locates a failure in the protocol without guessing from its text.
// Stage and Op are constants supplied by the code, never peer input.
type ConnError struct {
	Stage string
	Op    string
	Kind  FailureKind
	Err   error
}

func (e *ConnError) Error() string {
	return fmt.Sprintf("socks5 stage=%s op=%s kind=%s: %v", e.Stage, e.Op, e.Kind, e.Err)
}

func (e *ConnError) Unwrap() error { return e.Err }

func classifyFailure(err error) FailureKind {
	var ne net.Error
	var protocol interface{ ProtocolReason() string }
	switch {
	case errors.Is(err, context.Canceled):
		return FailureCanceled
	case errors.As(err, &ne) && ne.Timeout():
		return FailureTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return FailureClosed
	case errors.Is(err, ErrUserAuthFailed), errors.Is(err, ErrNoSupportedAuth):
		return FailureAuth
	case errors.Is(err, ErrSessionNotAllowed):
		return FailurePolicy
	case errors.As(err, &protocol):
		return FailureProtocol
	case errors.As(err, &ne):
		return FailureNetwork
	default:
		return FailureInternal
	}
}

func protocolReason(err error) string {
	var protocol interface{ ProtocolReason() string }
	if errors.As(err, &protocol) {
		return protocol.ProtocolReason()
	}
	return ""
}

func connFailure(stage, op string, err error) error {
	if err == nil {
		return nil
	}
	var classified *ConnError
	if errors.As(err, &classified) {
		return err
	}
	return &ConnError{Stage: stage, Op: op, Kind: classifyFailure(err), Err: err}
}

func protocolFailure(stage, op string, err error) error {
	return &ConnError{Stage: stage, Op: op, Kind: FailureProtocol, Err: err}
}

// failureCodes keeps joined causes visible without logging their raw text.
func failureCodes(err error) []string {
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		codes := make([]string, 0, len(many.Unwrap()))
		for _, cause := range many.Unwrap() {
			codes = append(codes, failureCodes(cause)...)
		}
		return codes
	}
	var failure *ConnError
	if errors.As(err, &failure) {
		return []string{failure.Stage + "." + failure.Op + ":" + string(failure.Kind)}
	}
	return nil
}
