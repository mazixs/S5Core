package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
)

// The kinds of UDP association, and the ways one that opened can end, that
// OnAssociationEnd reports. Both sets are closed, so a metric may take them
// as labels (docs/design/observability-policy.md).
const (
	AssociationPlain  = "associate" // 0x03
	AssociationTunnel = "tunnel"    // 0x83, and 0x84 without a native path
	AssociationNative = "native"    // 0x84 with a native path

	EndedByClient   = "client"
	EndedByReset    = "reset"
	EndedByTimeout  = "timeout"
	EndedByAccount  = "account"
	EndedByShutdown = "shutdown"
	EndedByError    = "error"
)

// AssociationKinds and AssociationEnds are the two closed sets.
func AssociationKinds() []string {
	return []string{AssociationPlain, AssociationTunnel, AssociationNative}
}

func AssociationEnds() []string {
	return []string{EndedByClient, EndedByReset, EndedByTimeout, EndedByAccount, EndedByShutdown, EndedByError}
}

// associationEnd names how an association ended from the error its handler
// returns. A client that closed its connection and one whose process died
// both end in EOF, so "client" says only that the server did not end it.
func associationEnd(err error) string {
	var ne net.Error
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return EndedByClient
	case errors.Is(err, ErrSessionNotAllowed):
		return EndedByAccount
	case errors.Is(err, context.Canceled):
		return EndedByShutdown
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return EndedByReset
	case errors.As(err, &ne) && ne.Timeout():
		return EndedByTimeout
	}
	return EndedByError
}

func (s *Server) associationEnded(req *Request, kind string, err error, egress *rotatingUDP) {
	reason := associationEnd(err)
	req.end.associationEnded(kind, reason, egress)
	if s.config.OnAssociationEnd != nil {
		s.config.OnAssociationEnd(kind, reason)
	}
}
