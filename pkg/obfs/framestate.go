package obfs

// FrameState is what the reader of an obfuscated connection is waiting for
// on the wire (plan task Ф6-1). It is reported through Config.OnFrameState
// and exists so that the connection's session can tell an idle peer from
// one that stopped in the middle of a frame - the two look the same to a
// plain idle timeout and deserve different deadlines.
type FrameState uint8

const (
	// FrameAwaitHeader: nothing of the next frame has arrived. This is
	// where an idle connection waits, and where the first read waits for
	// the prologue.
	FrameAwaitHeader FrameState = iota
	// FrameAwaitBody: the masked length arrived and the rest of the frame
	// has not. A peer that stays here has stopped mid-frame, or a middlebox
	// cut a segment; either way the reader can hand nothing up until the
	// frame completes.
	FrameAwaitBody
	// FrameDelivered: the last frame decoded and authenticated. Nothing is
	// awaited until the reader is asked for more.
	FrameDelivered
	// FrameRefused: the reader refused a frame - a bad tag, a length the
	// format cannot produce, a replay, a stream cut inside a frame. It is
	// the last state a connection reports.
	FrameRefused
)

func (s FrameState) String() string {
	switch s {
	case FrameAwaitHeader:
		return "await_header"
	case FrameAwaitBody:
		return "await_body"
	case FrameDelivered:
		return "delivered"
	case FrameRefused:
		return "refused"
	}
	return "unknown"
}

// setFrameState reports a change of state to the hook, and only a change:
// a reader that finds its bytes buffered stays where it was. The caller
// holds readMu.
func (c *conn) setFrameState(s FrameState) {
	if c.frameState == s || c.cfg.OnFrameState == nil {
		return
	}
	c.frameState = s
	c.cfg.OnFrameState(s)
}
