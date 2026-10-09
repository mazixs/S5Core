package socks5

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// Each association emits at most one malformed-header warning. Every
// discarded datagram is still recorded by udpDrop and the final journal.
// The log contains a fixed reason, never arbitrary peer data.
type udpWarningBudget struct{ invalid atomic.Bool }

func (b *udpWarningBudget) invalidHeader(logger *slog.Logger) {
	if b.invalid.CompareAndSwap(false, true) {
		logger.Warn("socks: invalid UDP header; further malformed headers counted", "reason", UDPDropInvalidHeader)
	}
}

// UDPRelayCounters describes socket/relay stages, not remote delivery. A
// successful WriteToUDP only means the local kernel accepted the datagram.
// Keep the hot path to atomic increments; metrics read these on collection.
type UDPRelayCounters struct {
	ClientIn, TargetOut, TargetIn, ClientOut atomic.Uint64
	Drops, TargetWriteErrors                 atomic.Uint64
}

type UDPRelaySnapshot struct {
	ClientIn, TargetOut, TargetIn, ClientOut uint64
	Drops, TargetWriteErrors                 uint64
}

func (c *UDPRelayCounters) Snapshot() UDPRelaySnapshot {
	return UDPRelaySnapshot{c.ClientIn.Load(), c.TargetOut.Load(), c.TargetIn.Load(), c.ClientOut.Load(),
		c.Drops.Load(), c.TargetWriteErrors.Load()}
}

func (v UDPRelaySnapshot) minus(old UDPRelaySnapshot) UDPRelaySnapshot {
	return UDPRelaySnapshot{v.ClientIn - old.ClientIn, v.TargetOut - old.TargetOut,
		v.TargetIn - old.TargetIn, v.ClientOut - old.ClientOut, v.Drops - old.Drops,
		v.TargetWriteErrors - old.TargetWriteErrors}
}

func (s *Server) udpClientIn(req *Request) {
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.ClientIn.Add(1)
	}
	if req.end != nil {
		req.end.udp.ClientIn.Add(1)
	}
}

func (s *Server) udpTargetOut(req *Request) {
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.TargetOut.Add(1)
	}
	if req.end != nil {
		req.end.udp.TargetOut.Add(1)
	}
}

func (s *Server) udpTargetIn(req *Request) {
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.TargetIn.Add(1)
	}
	if req.end != nil {
		req.end.udp.TargetIn.Add(1)
	}
}

func (s *Server) udpClientOut(req *Request) {
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.ClientOut.Add(1)
	}
	if req.end != nil {
		req.end.udp.ClientOut.Add(1)
	}
}

func (s *Server) udpDrop(req *Request, reason string) {
	s.countUDPDrop(reason)
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.Drops.Add(1)
	}
	if req.end != nil {
		req.end.udp.Drops.Add(1)
	}
}

func (s *Server) udpTargetWriteError(req *Request, err error) {
	s.udpDrop(req, udpWriteFailure(err))
	if s.config.UDPRelayCounters != nil {
		s.config.UDPRelayCounters.TargetWriteErrors.Add(1)
	}
	if req.end != nil {
		req.end.udp.TargetWriteErrors.Add(1)
	}
}

// No error text reaches a metric: net.OpError includes the target address.
func udpWriteFailure(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, net.ErrClosed):
		return UDPDropTargetClosed
	case errors.As(err, &ne) && ne.Timeout():
		return UDPDropTargetTimeout
	case errors.Is(err, syscall.EMSGSIZE):
		return UDPDropTargetTooLarge
	case errors.Is(err, syscall.ENOBUFS):
		return UDPDropTargetNoBuffer
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ECONNREFUSED):
		return UDPDropTargetUnreachable
	default:
		return UDPDropTargetOther
	}
}

// startUDPReport is opt-in. The server layer logs only counters and the
// secret-derived log ID at Debug; this codec does not inspect the transport.
// The timer is stopped before the association ends.
func (s *Server) startUDPReport(ctx context.Context, req *Request, conn net.Conn) func() {
	interval := s.config.UDPDiagnosticsInterval
	if interval == 0 || req.end == nil || s.config.OnUDPReport == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var last UDPRelaySnapshot
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := req.end.udp.Snapshot()
				if now == (UDPRelaySnapshot{}) {
					continue
				}
				delta := now.minus(last)
				s.config.OnUDPReport(conn, now, delta)
				last = now
			}
		}
	}()
	return func() { cancel(); <-done }
}

func ValidateUDPDiagnosticsInterval(interval time.Duration) error {
	if interval < 0 || interval > 0 && interval < time.Second {
		return errors.New("UDP_DIAGNOSTICS_INTERVAL must be 0 (off) or at least 1s")
	}
	return nil
}
