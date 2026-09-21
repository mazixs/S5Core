package obfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Control frames with a payload (plan task Ф5-7).
//
// A keepalive and a FIN carry nothing; the two kinds below carry a few
// bytes each, once per connection and per direction. They exist because a
// tunnel whose clients sit on routers and are updated by hand needs two
// things it did not have: a way for the server to learn which builds are
// out there, and a way for it to tell them which transport to use next -
// without a release, and without a side channel that would have to be
// authenticated all over again.
//
// Both ride inside the AEAD, so on the wire they are frames of the usual
// look. Both go out ahead of the first data frame of their sender, in the
// same write, so neither costs a round trip nor a packet of its own: the
// client's first packet is still "prologue plus frames", the server's first
// packet is still its SOCKS5 answer. Gate G4 measured the connection setup
// at 4 RTT with none spent on this layer, and that stays true.
//
// The payload is a sequence of TLVs - a type byte, a length byte and the
// value - so that a field can be added later without a new frame kind.
// A receiver skips types it does not know; a peer that knows more fields
// than this build is not an error, it is the situation these frames exist
// for.

// Hello is what a client says about itself when the tunnel opens. It is
// what makes "which versions are out there, and on which transport" a
// number on the server instead of a guess.
type Hello struct {
	// Version is the client's build, as internal/buildinfo reports it.
	// Longer than maxControlString bytes is cut, not refused.
	Version string
	// Transport is the transport the client believes it is on: "obfs" or
	// "ws". The server knows which listener the connection came in on and
	// treats this as the client's opinion, useful when the two disagree.
	Transport string
}

// Advice is what a server recommends to a client, once, when the tunnel
// opens. A zero field means the server has no opinion on it; a client
// applies what it can to its next connections, never to the current one.
//
// It is a recommendation, not a command: the client may be pinned to a
// transport by its operator, may lack the configuration the advised
// transport needs, or may have just watched that transport fail. What the
// client does with it is the client's policy; this layer only carries it.
type Advice struct {
	// Transport is the transport the server would rather see this client
	// on: "obfs" or "ws". Empty leaves the client where it is.
	Transport string

	// The shape a client should give its traffic from now on. These mirror
	// the client's own configuration knobs, so that a shape decided by the
	// operator on the server reaches a router nobody can log in to. All are
	// sender-side settings on the client, which is why the server can hand
	// them out without changing anything about itself.
	WSMinFrame    int
	WSMaxFrame    int
	WSMaxJitterMs int
	MaxPadding    int
	KeepaliveMin  time.Duration
	KeepaliveMax  time.Duration
}

// TLV types. Hello and Advice have separate namespaces: the kind byte of the
// frame says which one applies.
const (
	helloVersion   = 0x01
	helloTransport = 0x02

	adviceTransport    = 0x01
	adviceWSMinFrame   = 0x02
	adviceWSMaxFrame   = 0x03
	adviceWSMaxJitter  = 0x04
	adviceMaxPadding   = 0x05
	adviceKeepaliveMin = 0x06
	adviceKeepaliveMax = 0x07
)

// maxControlString bounds every string field. A version is a tag or a
// short revision; a transport name is a word. Anything longer is somebody
// else's data and is cut at the sender.
const maxControlString = 32

// maxControlPayload bounds the whole payload of a control frame, so that it
// fits in one frame of any MTU this format accepts and so that a receiver
// knows the most it will ever have to parse.
const maxControlPayload = 255

// encodeHello turns a Hello into its TLV payload.
func encodeHello(h Hello) []byte {
	var out []byte
	out = appendStringTLV(out, helloVersion, h.Version)
	out = appendStringTLV(out, helloTransport, h.Transport)
	return out
}

// decodeHello parses a Hello. Unknown types are skipped.
func decodeHello(payload []byte) (Hello, error) {
	var h Hello
	err := walkTLV(payload, func(typ byte, value []byte) error {
		switch typ {
		case helloVersion:
			h.Version = string(value)
		case helloTransport:
			h.Transport = string(value)
		}
		return nil
	})
	return h, err
}

// encodeAdvice turns an Advice into its TLV payload. Zero fields are left
// out rather than sent as zero, so "no opinion" costs nothing on the wire
// and decodes back to the zero value.
func encodeAdvice(a Advice) []byte {
	var out []byte
	out = appendStringTLV(out, adviceTransport, a.Transport)
	out = appendUint16TLV(out, adviceWSMinFrame, a.WSMinFrame)
	out = appendUint16TLV(out, adviceWSMaxFrame, a.WSMaxFrame)
	out = appendUint16TLV(out, adviceWSMaxJitter, a.WSMaxJitterMs)
	out = appendUint16TLV(out, adviceMaxPadding, a.MaxPadding)
	out = appendUint16TLV(out, adviceKeepaliveMin, int(a.KeepaliveMin/time.Second))
	out = appendUint16TLV(out, adviceKeepaliveMax, int(a.KeepaliveMax/time.Second))
	return out
}

// decodeAdvice parses an Advice. Unknown types are skipped; a numeric field
// of the wrong width is an error, because a peer that agrees on the type
// and not on the width is a peer this build cannot follow.
func decodeAdvice(payload []byte) (Advice, error) {
	var a Advice
	err := walkTLV(payload, func(typ byte, value []byte) error {
		switch typ {
		case adviceTransport:
			a.Transport = string(value)
			return nil
		case adviceWSMinFrame, adviceWSMaxFrame, adviceWSMaxJitter, adviceMaxPadding, adviceKeepaliveMin, adviceKeepaliveMax:
			if len(value) != 2 {
				return fmt.Errorf("advice field 0x%02x is %d bytes, want 2", typ, len(value))
			}
			n := int(binary.BigEndian.Uint16(value))
			switch typ {
			case adviceWSMinFrame:
				a.WSMinFrame = n
			case adviceWSMaxFrame:
				a.WSMaxFrame = n
			case adviceWSMaxJitter:
				a.WSMaxJitterMs = n
			case adviceMaxPadding:
				a.MaxPadding = n
			case adviceKeepaliveMin:
				a.KeepaliveMin = time.Duration(n) * time.Second
			case adviceKeepaliveMax:
				a.KeepaliveMax = time.Duration(n) * time.Second
			}
		}
		return nil
	})
	return a, err
}

// appendStringTLV appends one string field, cut to maxControlString. An
// empty string is not sent at all.
func appendStringTLV(out []byte, typ byte, s string) []byte {
	if s == "" {
		return out
	}
	if len(s) > maxControlString {
		s = s[:maxControlString]
	}
	out = append(out, typ, byte(len(s)))
	return append(out, s...)
}

// appendUint16TLV appends one 16-bit field. Zero is not sent; a value that
// does not fit is clamped, because every field this carries is a length or
// a count of seconds and 65535 of either is already "as much as possible".
func appendUint16TLV(out []byte, typ byte, n int) []byte {
	if n <= 0 {
		return out
	}
	if n > 0xFFFF {
		n = 0xFFFF
	}
	return append(out, typ, 2, byte(n>>8), byte(n))
}

// errControlTruncated is a TLV cut off inside a field.
var errControlTruncated = errors.New("control frame payload is truncated inside a field")

// walkTLV calls visit for every type-length-value in payload. A length that
// runs past the end is an error: the frame authenticated, so this is a peer
// that speaks a different encoding, and guessing what it meant is not an
// option.
func walkTLV(payload []byte, visit func(typ byte, value []byte) error) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("control frame payload is %d bytes, the format allows %d", len(payload), maxControlPayload)
	}
	for len(payload) > 0 {
		if len(payload) < 2 {
			return errControlTruncated
		}
		typ, n := payload[0], int(payload[1])
		payload = payload[2:]
		if n > len(payload) {
			return errControlTruncated
		}
		if err := visit(typ, payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// pendingControl is a control frame waiting to ride ahead of the first frame
// this end writes.
type pendingControl struct {
	kind    frameKind
	payload []byte
}

// queueControl prepares the control frame this end sends when it first
// writes, and checks that it fits in one frame at this MTU. Called from
// NewConn before the connection is handed out, so a Hello that does not fit
// is a configuration error, not a failed write later.
func (c *conn) queueControl(kind frameKind, payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("obfs: %s payload is %d bytes, the format allows %d", kind, len(payload), maxControlPayload)
	}
	if len(payload) > c.payloadBudget {
		return fmt.Errorf("obfs: %s payload is %d bytes, MTU %d leaves room for %d", kind, len(payload), c.cfg.MTU, c.payloadBudget)
	}
	c.pending = &pendingControl{kind: kind, payload: payload}
	return nil
}

// flushPendingLocked encodes the queued control frame, if any, into buf and
// returns its length on the wire. The caller holds writeMu and has room for
// one whole frame at buf.
func (c *conn) flushPendingLocked(buf []byte) int {
	p := c.pending
	if p == nil {
		return 0
	}
	c.pending = nil
	return c.encodePayloadControl(buf, p.kind, p.payload)
}

// encodePayloadControl builds one frame of the given kind that carries a
// payload. It pads the way a data frame pads - a draw up to the padding cap
// - rather than the way an empty control frame does, because it goes out in
// the same write as data frames and should be sized like one of them, not
// like a frame the connection sent earlier: there is no earlier.
func (c *conn) encodePayloadControl(buf []byte, kind frameKind, payload []byte) int {
	padLen := 0
	if c.padCap > 0 {
		padLen = int(c.randUint16()) % (c.padCap + 1)
	}
	if padLen > c.payloadBudget-len(payload) {
		padLen = c.payloadBudget - len(payload)
	}

	plaintextLen := 1 + 2 + len(payload) + 2 + padLen
	pt := buf[2 : 2+plaintextLen]
	pt[0] = byte(kind)
	binary.BigEndian.PutUint16(pt[1:3], uint16(len(payload)))
	copy(pt[3:], payload)
	binary.BigEndian.PutUint16(pt[3+len(payload):], uint16(padLen))
	clear(pt[3+len(payload)+2:])

	counter := c.writeCounter
	c.writeCounter++

	ciphertext := c.aeadSend.Seal(buf[2:2], c.sendNonce(counter), pt, nil)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ciphertext))^c.sendMask(counter))
	return 2 + len(ciphertext)
}

// deliverControl hands a hello or an advice to the callback configured for
// it. Only the first of each kind on a connection is delivered: the second
// is a peer repeating itself, and a counter fed by repeats is a counter the
// peer controls.
//
// A frame addressed to the wrong role - a hello arriving at a client, an
// advice at a server - is dropped, not refused. It is authentic, harmless
// and says nothing this end acts on.
func (c *conn) deliverControl(kind frameKind, payload []byte) error {
	switch kind {
	case kindHello:
		if c.cfg.Role != RoleServer || c.helloSeen {
			return nil
		}
		c.helloSeen = true
		h, err := decodeHello(payload)
		if err != nil {
			return err
		}
		if c.cfg.OnHello != nil {
			c.cfg.OnHello(h)
		}
	case kindAdvice:
		if c.cfg.Role != RoleClient || c.adviceSeen {
			return nil
		}
		c.adviceSeen = true
		a, err := decodeAdvice(payload)
		if err != nil {
			return err
		}
		if c.cfg.OnAdvice != nil {
			c.cfg.OnAdvice(a)
		}
	}
	return nil
}

// String names a frame kind in errors.
func (k frameKind) String() string {
	switch k {
	case kindData:
		return "data"
	case kindKeepalive:
		return "keepalive"
	case kindFIN:
		return "FIN"
	case kindHello:
		return "hello"
	case kindAdvice:
		return "advice"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}
