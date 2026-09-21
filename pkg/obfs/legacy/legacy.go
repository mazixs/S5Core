// Package legacy carries the obfuscation format that preceded docs/veil-spec.md,
// so that a client built today can still reach a server that has not been
// updated (plan task Ф5-7). It is the migration window, not a transport:
// s5client uses it only when OBFS_FORMAT says so, or when OBFS_FORMAT=auto
// and the current format was refused. The server side of S5Core does not
// speak it any more.
//
// Removal is scheduled two minor releases after the first release that
// carries the current format; docs/field/migration.md has the schedule and
// the order in which a fleet is moved.
//
// The wire format, unchanged from the original:
//
//	[FrameLen 4B big-endian = len(Nonce)+len(Ciphertext)]
//	[Nonce 12B random]
//	[AES-256-GCM(PSK)([PayloadLen 2B][Payload][PadLen 2B][Padding])]
//
// There is no prologue, no key derivation, no frame kind and no length mask:
// the PSK is the AEAD key, the nonce is random per frame and travels in the
// clear, and the frame length is visible on the wire. All of that is why the
// format was replaced (docs/gates/g3-wire-format.md), and why a client on it is on it
// only until its server moves.
package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// DefaultMTU is the frame size the original format defaulted to. It is a
// buffer hint only: the original never cut its writes to it.
const DefaultMTU = 1400

// maxFrame is the largest frame the reader accepts, the original's ceiling.
const maxFrame = 131072

// maxPayload is the most one Write carries; the payload length is 16 bits.
const maxPayload = 65535

// Config is the subset of the original settings the format needs.
type Config struct {
	// PSK is the AEAD key: 32 bytes, used directly.
	PSK []byte
	// MaxPadding bounds the random padding on each frame.
	MaxPadding int
	// MTU sizes the read buffer. Zero means DefaultMTU.
	MTU int
}

// conn is the original wrapper, trimmed to what a client needs.
type conn struct {
	net.Conn
	cfg  Config
	aead cipher.AEAD

	writeBuf []byte
	nonce    []byte

	randBuf [4096]byte
	randPos int

	readHdr  [4]byte
	readBuf  []byte
	readRest []byte
}

// NewConn wraps c in the original format. Both ends ran the same code, so
// there is no role: a test can use it as the server a client of this format
// expects to find.
func NewConn(c net.Conn, cfg Config) (net.Conn, error) {
	if len(cfg.PSK) != 32 {
		return nil, errors.New("legacy obfs: PSK must be 32 bytes")
	}
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MaxPadding < 0 {
		return nil, errors.New("legacy obfs: MaxPadding must not be negative")
	}

	block, err := aes.NewCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("legacy obfs: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("legacy obfs: %w", err)
	}

	nonceSize := aead.NonceSize()
	maxPlaintext := 2 + maxPayload + 2 + cfg.MaxPadding
	writeBufSize := 4 + nonceSize + maxPlaintext + aead.Overhead()

	return &conn{
		Conn:     c,
		cfg:      cfg,
		aead:     aead,
		writeBuf: make([]byte, writeBufSize),
		nonce:    make([]byte, nonceSize),
		readBuf:  make([]byte, max(cfg.MTU*2, 4096)),
		randPos:  4096, // force a fill on first use
	}, nil
}

func (c *conn) randBytes(dst []byte) {
	for len(dst) > 0 {
		if c.randPos >= len(c.randBuf) {
			_, _ = io.ReadFull(rand.Reader, c.randBuf[:])
			c.randPos = 0
		}
		n := copy(dst, c.randBuf[c.randPos:])
		c.randPos += n
		dst = dst[n:]
	}
}

func (c *conn) randUint16() uint16 {
	var b [2]byte
	c.randBytes(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// Write sends b as one frame. The original refused anything over 65535
// bytes rather than splitting it; io.Copy never hands over that much, and
// a caller that does gets the same error the original gave.
func (c *conn) Write(b []byte) (int, error) {
	if len(b) > maxPayload {
		return 0, errors.New("legacy obfs: payload too large")
	}

	padLen := 0
	if c.cfg.MaxPadding > 0 {
		padLen = int(c.randUint16()) % (c.cfg.MaxPadding + 1)
	}

	nonceSize := c.aead.NonceSize()
	plaintextStart := 4 + nonceSize
	plaintextLen := 2 + len(b) + 2 + padLen

	pt := c.writeBuf[plaintextStart : plaintextStart+plaintextLen]
	binary.BigEndian.PutUint16(pt[0:2], uint16(len(b)))
	copy(pt[2:], b)
	binary.BigEndian.PutUint16(pt[2+len(b):], uint16(padLen))
	if padLen > 0 {
		c.randBytes(pt[2+len(b)+2:])
	}

	c.randBytes(c.nonce)
	copy(c.writeBuf[4:4+nonceSize], c.nonce)
	ciphertext := c.aead.Seal(c.writeBuf[plaintextStart:plaintextStart], c.nonce, pt, nil)

	frameSize := nonceSize + len(ciphertext)
	binary.BigEndian.PutUint32(c.writeBuf[0:4], uint32(frameSize))
	if _, err := c.Conn.Write(c.writeBuf[:4+frameSize]); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read returns the payload of the next frame, buffering what did not fit.
func (c *conn) Read(b []byte) (int, error) {
	if len(c.readRest) > 0 {
		n := copy(b, c.readRest)
		c.readRest = c.readRest[n:]
		return n, nil
	}

	if _, err := io.ReadFull(c.Conn, c.readHdr[:]); err != nil {
		return 0, err
	}
	frameSize := binary.BigEndian.Uint32(c.readHdr[:])
	if frameSize > maxFrame {
		return 0, errors.New("legacy obfs: frame too large")
	}

	var frame []byte
	if int(frameSize) <= cap(c.readBuf) {
		frame = c.readBuf[:frameSize]
	} else {
		frame = make([]byte, frameSize)
	}
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	nonceSize := c.aead.NonceSize()
	if len(frame) < nonceSize {
		return 0, errors.New("legacy obfs: invalid frame")
	}
	nonce, ciphertext := frame[:nonceSize], frame[nonceSize:]
	plaintext, err := c.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("legacy obfs: failed to decrypt: %w", err)
	}
	if len(plaintext) < 4 {
		return 0, errors.New("legacy obfs: invalid plaintext format")
	}
	payloadLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if len(plaintext) < 2+payloadLen+2 {
		return 0, errors.New("legacy obfs: invalid payload length")
	}

	payload := plaintext[2 : 2+payloadLen]
	copied := copy(b, payload)
	if copied < len(payload) {
		c.readRest = append(c.readRest[:0], payload[copied:]...)
	}
	return copied, nil
}

type closeWriter interface {
	CloseWrite() error
}

// CloseWrite is the original's: the format has no FIN of its own, so the
// half-close is the transport's or nothing.
func (c *conn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("legacy obfs: underlying connection does not support CloseWrite")
}

// NetConn exposes the transport underneath, the way pkg/obfs does.
func (c *conn) NetConn() net.Conn { return c.Conn }
