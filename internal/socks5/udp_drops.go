package socks5

const (
	UDPDropDNSPending        = "dns_pending"
	UDPDropFrameOversize     = "frame_oversize"
	UDPDropDNSFailed         = "dns_failed"
	UDPDropInvalidHeader     = "invalid_header"
	UDPDropSourceMismatch    = "source_mismatch"
	UDPDropRules             = "rules_denied"
	UDPDropPrivate           = "private_dest"
	UDPDropClientWrite       = "client_write"
	UDPDropClientUnknown     = "client_unknown"
	UDPDropTargetClosed      = "target_write_closed"
	UDPDropTargetTimeout     = "target_write_timeout"
	UDPDropTargetTooLarge    = "target_write_too_large"
	UDPDropTargetNoBuffer    = "target_write_no_buffer"
	UDPDropTargetUnreachable = "target_write_unreachable"
	UDPDropTargetOther       = "target_write_other"
)

func UDPDropReasons() []string {
	return []string{UDPDropDNSPending, UDPDropFrameOversize, UDPDropDNSFailed,
		UDPDropInvalidHeader, UDPDropSourceMismatch, UDPDropRules, UDPDropPrivate,
		UDPDropClientWrite, UDPDropClientUnknown, UDPDropTargetClosed, UDPDropTargetTimeout,
		UDPDropTargetTooLarge, UDPDropTargetNoBuffer, UDPDropTargetUnreachable, UDPDropTargetOther}
}

func (s *Server) countUDPDrop(reason string) {
	if s.config.OnUDPDrop != nil {
		s.config.OnUDPDrop(reason)
	}
}
