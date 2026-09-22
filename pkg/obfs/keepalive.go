package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"
)

// Plan task Ф4-8. Three requirements pull against each other only while the
// interval is fixed:
//
//   - a long session must not be dropped by whatever sits on the path.
//     Measured: s5core itself after READ_TIMEOUT, 30 s by default and the
//     shortest of them all, nginx after proxy_read_timeout, 60 s by default.
//     Published: Cloudflare about 100 s on Free and Pro, AWS NAT Gateway
//     350 s, Azure Load Balancer 4 minutes. The interval has to clear the
//     shortest one, which turned out to be ours - see the keepalive table in
//     README and scripts/keepalive_matrix.sh.
//   - a dead connection must not hold a slot, which is the read deadline's
//     job, not this one's: a keepalive that arrives keeps the peer's deadline
//     fresh, and one that stops arriving lets it fire.
//   - the traffic must not draw a recognisable shape, and a frame every 45.0
//     seconds is the most recognisable shape there is.
//
// The three are satisfied together by drawing the idle interval anew each
// time, by suppressing the frame when real traffic has already held the path
// open, and by giving the frame the length of a frame this connection has
// really sent.

// DefaultKeepaliveMin and DefaultKeepaliveMax are what the client uses unless
// configured otherwise. The range was first set from the published network
// figures - 45-75 s - and every row of the matrix came back broken at 30 s,
// because the shortest idle timeout on the path was our own READ_TIMEOUT. The
// upper bound therefore sits well under it, with room for one lost frame, and
// the spread is wide enough that the intervals do not pile up on a value.
// WireGuard's persistent keepalive is 25 s and OpenVPN's default ping is 10 s,
// which is the same order.
const (
	DefaultKeepaliveMin = 10 * time.Second
	DefaultKeepaliveMax = 20 * time.Second
)

// startKeepalive launches the idle timer, if one was asked for.
func (c *conn) startKeepalive() {
	if c.cfg.KeepaliveMin <= 0 {
		return
	}
	go c.keepaliveLoop()
}

func (c *conn) keepaliveLoop() {
	interval := c.keepaliveDelay()
	anchor := c.lastWriteAt()
	for {
		// Recheck against the same target idle interval after application
		// traffic, rather than starting a new full wait at suppression time.
		last := c.lastWriteAt()
		if last.Before(anchor) {
			last = anchor
		}
		wait := interval - time.Since(last)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-c.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		if time.Since(c.lastWriteAt()) < interval {
			continue
		}
		if err := c.writeKeepalive(); err != nil {
			return
		}
		anchor = c.lastWriteAt()
		if !anchor.After(last) {
			anchor = time.Now()
		} // no opening sent yet
		interval = c.keepaliveDelay()
	}
}

// keepaliveDelay draws the next idle interval. It is drawn from crypto/rand,
// not from the buffered source the write path uses: the sequence of intervals
// is observable from outside, so it must not be predictable from anything an
// observer has already seen. One draw per interval is free at this rate.
func (c *conn) keepaliveDelay() time.Duration {
	lo, hi := c.cfg.KeepaliveMin, c.cfg.KeepaliveMax
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		return lo
	}
	return lo + time.Duration(n.Int64())
}

// writeKeepalive sends one frame that carries no payload.
func (c *conn) writeKeepalive() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.sendReady.Load() || !c.prologueSent {
		// Nothing has gone out yet on this connection. There is no idle path
		// to hold open, and starting one with a keepalive would make the
		// first frame of a connection a frame with no payload - a shape of
		// its own, and one the peer would be alone in having.
		return nil
	}
	if c.writeClosed {
		// This half is over: the peer has had its FIN and has stopped
		// reading. Frames after it would hold a path open for a direction
		// that no longer exists.
		return errWriteClosed
	}

	return c.writeControlLocked(kindKeepalive)
}

// writeControlLocked sends one frame of the given kind, padded to the length
// of a frame this connection has already sent. The caller holds writeMu.
//
// It is the write path of everything that is not payload - keepalives and the
// FIN - and it is one function because the two must be indistinguishable on
// the wire from each other and from a data frame.
func (c *conn) writeControlLocked(kind frameKind) error {
	off := 0
	if !c.prologueSent {
		// A client that closes its write half without ever having written
		// still has to send its opening: without it the peer cannot derive
		// the keys the FIN frame is sealed with.
		//
		// The opening, not the prologue. These two used to differ here
		// (review finding R04): this branch wrote the raw 32 bytes while the
		// data path wrote c.wirePrologue, so a connection that half-closed
		// before its first Write opened with a shape the default encoding
		// exists to avoid - and lost the filter exemption measured in
		// docs/field/stealth.md, where a raw prologue was refused on 45 of 48
		// connections and an encoded one on none of 78.
		c.prologueSent = true
		if c.cfg.SplitOpening {
			if _, err := c.Conn.Write(c.wirePrologue); err != nil {
				return err
			}
			c.markWrite()
		} else {
			off = copy(c.writeBuf, c.wirePrologue)
		}
	}
	// A hello queued on a connection that never wrote data still goes out
	// ahead of its FIN, for the same reason the salt does: the peer has a
	// use for it, and this is the last write.
	off += c.flushPendingLocked(c.writeBuf[off : off+c.maxFrame])

	n := c.encodeControl(c.writeBuf[off:off+c.maxFrame], kind)
	if _, err := c.Conn.Write(c.writeBuf[:off+n]); err != nil {
		return err
	}
	c.markWrite()
	return nil
}

// encodeControl builds a frame whose payload is empty and whose padding takes
// the whole length of a frame this connection has sent before. The caller
// holds writeMu.
func (c *conn) encodeControl(buf []byte, kind frameKind) int {
	wire := c.recentSize()
	padLen := wire - frameOverhead
	if padLen < 0 {
		padLen = 0
	}
	if padLen > c.payloadBudget {
		padLen = c.payloadBudget
	}

	plaintextLen := 1 + 2 + 0 + 2 + padLen
	pt := buf[2 : 2+plaintextLen]
	pt[0] = byte(kind)
	binary.BigEndian.PutUint16(pt[1:3], 0)
	binary.BigEndian.PutUint16(pt[3:5], uint16(padLen))
	clear(pt[5:])

	counter := c.writeCounter
	c.writeCounter++

	ciphertext := c.aeadSend.Seal(buf[2:2], c.sendNonce(counter), pt, nil)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ciphertext))^c.sendMask(counter))
	return 2 + len(ciphertext)
}

// recentSize picks the wire length of one of the last frames this connection
// sent. Copying a real length is what makes the keepalive indistinguishable
// by size; a connection that has sent nothing yet - the server on a session
// where only the client has spoken - falls back to a draw across the range a
// data frame can occupy.
func (c *conn) recentSize() int {
	if c.recentLen == 0 {
		return frameOverhead + 1 + int(c.randUint16())%c.payloadBudget
	}
	return c.recentSizes[int(c.randUint16())%c.recentLen]
}

// markWrite records that something went out just now.
func (c *conn) markWrite() { c.lastWrite.Store(time.Now().UnixNano()) }

func (c *conn) lastWriteAt() time.Time { return time.Unix(0, c.lastWrite.Load()) }

// Close stops the keepalive timer and closes the connection underneath.
func (c *conn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.Conn.Close()
}
