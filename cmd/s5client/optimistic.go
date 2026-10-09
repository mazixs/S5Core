package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// optimisticReply is the success an application gets before the tunnel
// exists. The bound address is unknown at that moment.
var optimisticReply = []byte{socks5Ver, socks5Success, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

// refusedError is a CONNECT the server answered with a failure code.
type refusedError struct{ code byte }

func (e *refusedError) Error() string { return fmt.Sprintf("CONNECT refused: 0x%02x", e.code) }

// connectOptimistically serves a CONNECT under OPTIMISTIC_CONNECT
// (docs/plan/v2.4-rc4.md, decision 1). The application hears success at
// once, its bytes follow the request into the tunnel as they come, and the
// server keeps them past its handshake (internal/socks5, Request.bufConn), so
// nothing waits a round trip for the reply. Nothing waits for the
// application either: a protocol where the server speaks first works as it
// did, and the first packet on the wire is the same one as without this.
//
// The reply is read where the downstream starts. A refusal or a failed setup
// can no longer be a reply code, so the application gets a reset, and the log
// and the minute counters say what they say without this.
func connectOptimistically(clientConn net.Conn, cfg clientParams, req []byte, dest string) {
	setupStart := time.Now()
	if _, err := clientConn.Write(optimisticReply); err != nil {
		return
	}

	attempt := cfg.attempt()
	attempt.deferGreeting = true
	obfsConn, cfg, err := dialAttempt(attempt, req)
	if err != nil {
		logTunnelFailure(err, dest, cfg)
		resetConn(clientConn)
		return
	}
	defer obfsConn.Close()

	// Written by the downstream before relayAfter returns.
	var replyAt time.Time
	r := relayAfter(clientConn, obfsConn, func() error {
		code, err := awaitConnectReply(obfsConn, cfg)
		if err != nil {
			return err
		}
		replyAt = time.Now()
		if code != socks5Success {
			return &refusedError{code: code}
		}
		// The handshake deadline has bounded the upstream's writes too; both
		// transports take a deadline change while another goroutine writes.
		clearDeadline(obfsConn)
		tuneStream(obfsConn, cfg.TunnelDeadTimeout)
		noteFastOpen(obfsConn)
		return nil
	})

	id := obfs.LogIDOf(obfsConn)
	var refused *refusedError
	switch {
	case r.awaitErr == nil:
		logRelayEnd(id, dest, cfg, replyAt.Sub(setupStart), replyAt, r)
	case r.abortedByUp:
		// The application went away before the server answered: before the
		// reply only a failed read of the application aborts the tunnel.
		closedBy := relayClosedBy(r.up, true)
		minutes.tcpClosed(closedBy)
		logTCPClosed(id, dest, cfg, time.Since(setupStart), 0, r.up.n, 0, closedBy, r.up.err)
	case errors.As(r.awaitErr, &refused):
		minutes.tcpClosed(closedByServer)
		logTCPClosed(id, dest, cfg, time.Since(setupStart), 0, r.up.n, 0, closedByServer, nil, "reply", refused.code)
	default:
		if cfg.policy != nil && countsAgainstThePath(r.awaitErr) {
			cfg.policy.onFailure(cfg, tunnelPhaseOf(r.awaitErr))
		}
		logTunnelFailure(r.awaitErr, dest, cfg)
	}
}

// greetingDeferred says whether dialObfsTunnel leaves the reply to the
// greeting unread: only a greeting pipelined with the request can.
func (cfg clientParams) greetingDeferred() bool {
	return cfg.deferGreeting && cfg.ProxyUser == ""
}

// awaitConnectReply reads what the server says to an optimistic CONNECT: the
// reply to the greeting when the dial left it, then the reply to the request.
// It returns the reply code. The answered greeting is the success the policy
// hears, as dialAttempt reports it when it reads the greeting itself.
func awaitConnectReply(c net.Conn, cfg clientParams) (byte, error) {
	if cfg.greetingDeferred() {
		method, err := readGreeting(c)
		if err != nil {
			return 0, err
		}
		if method != socks5NoAuth {
			return 0, methodRefused(method)
		}
		if cfg.policy != nil {
			cfg.policy.onSuccess(cfg)
		}
	}
	reply, err := readSOCKSReply(c)
	if err != nil {
		return 0, &tunnelError{phase: phaseConnectReply, err: err}
	}
	return reply[1], nil
}

// readServerGreeting reads the method the server chose.
func readServerGreeting(r io.Reader) (byte, error) {
	var resp [2]byte
	if _, err := io.ReadFull(r, resp[:]); err != nil {
		return 0, tunnelFail(phaseGreeting, "failed to read server greeting: %w", err)
	}
	if resp[0] != socks5Ver {
		return 0, tunnelFail(phaseAuthRejected, "unsupported SOCKS version: 0x%02x", resp[0])
	}
	return resp[1], nil
}

// methodRefused is the failure for a method this client cannot go on with.
func methodRefused(method byte) error {
	switch method {
	case socks5UserPassAuth:
		return tunnelFail(phaseAuthRejected, "server requires auth but PROXY_USER not set")
	case 0xFF:
		return tunnelFail(phaseAuthRejected, "server rejected all auth methods")
	}
	return tunnelFail(phaseAuthRejected, "unsupported auth method: 0x%02x", method)
}
