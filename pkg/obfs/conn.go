package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// DefaultMTU is the default maximum frame size on the wire.
const DefaultMTU = 1400

// Config holds the configuration for the obfuscation layer.
type Config struct {
	// PSK is the pre-shared key for AES-GCM encryption (must be 32 bytes for AES-256).
	PSK []byte
	// MaxPadding is the maximum random padding length added to each frame.
	MaxPadding int
	// MTU is the maximum transmission unit for obfuscated frames.
	// If zero, DefaultMTU (1400) is used.
	MTU int
}

// conn is the obfuscation wrapper around net.Conn.
type conn struct {
	net.Conn
	cfg  Config
	aead cipher.AEAD

	// Pre-allocated write buffers (owned by single goroutine per direction,
	// so no mutex needed — net.Conn guarantees sequential Write calls).
	writeBuf []byte // reusable buffer for building the wire frame
	nonce    []byte // reusable nonce buffer

	// Buffered random source — reduces crypto/rand syscalls from
	// 2 per frame to ~1 per 300+ frames (4KB buffer / ~12 bytes per frame).
	randBuf [4096]byte
	randPos int

	// Pre-allocated read buffers
	readHdr  [4]byte // frame header
	readBuf  []byte  // reusable frame read buffer
	readRest []byte  // unconsumed payload from previous Read
}

// bufferPool for large frame buffers used in Read when readBuf is too small.
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2*1024*1024)
		return &b
	},
}

// NewConn wraps an existing net.Conn with obfuscation.
func NewConn(c net.Conn, cfg Config) (net.Conn, error) {
	if len(cfg.PSK) != 32 {
		return nil, fmt.Errorf("obfs: PSK must be 32 bytes")
	}

	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}

	block, err := aes.NewCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("obfs: failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("obfs: failed to create GCM: %w", err)
	}

	nonceSize := aead.NonceSize()
	// Pre-allocate write buffer large enough for: 4 (header) + nonceSize + max plaintext + GCM tag + padding
	maxPlaintext := 2 + 65535 + 2 + cfg.MaxPadding
	maxCiphertext := maxPlaintext + aead.Overhead()
	writeBufSize := 4 + nonceSize + maxCiphertext

	// Pre-allocate read buffer for typical frames
	readBufSize := cfg.MTU * 2
	if readBufSize < 4096 {
		readBufSize = 4096
	}

	oc := &conn{
		Conn:     c,
		cfg:      cfg,
		aead:     aead,
		writeBuf: make([]byte, writeBufSize),
		nonce:    make([]byte, nonceSize),
		readBuf:  make([]byte, readBufSize),
		randPos:  4096, // force fill on first use
	}

	return oc, nil
}

// randBytes fills dst with random bytes from the buffered source.
// This batches crypto/rand syscalls to reduce overhead.
func (c *conn) randBytes(dst []byte) {
	for len(dst) > 0 {
		if c.randPos >= len(c.randBuf) {
			io.ReadFull(rand.Reader, c.randBuf[:])
			c.randPos = 0
		}
		n := copy(dst, c.randBuf[c.randPos:])
		c.randPos += n
		dst = dst[n:]
	}
}

// randUint16 returns a random uint16 from the buffered source.
func (c *conn) randUint16() uint16 {
	var b [2]byte
	c.randBytes(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// Write implements net.Conn.Write with obfuscation.
// Protocol: [FrameLen 4B] [Nonce 12B] [AES-GCM([PayloadLen 2B][Payload][PadLen 2B][Padding])]
//
// Zero-alloc hot path: all buffers are pre-allocated and reused.
func (c *conn) Write(b []byte) (int, error) {
	if len(b) > 65535 {
		return 0, fmt.Errorf("obfs: payload too large")
	}

	// Determine padding length — zero-alloc, uses buffered random
	padLen := 0
	if c.cfg.MaxPadding > 0 {
		padLen = int(c.randUint16()) % (c.cfg.MaxPadding + 1)
	}

	// Build plaintext directly in writeBuf after header+nonce space
	nonceSize := c.aead.NonceSize()
	plaintextStart := 4 + nonceSize
	plaintextLen := 2 + len(b) + 2 + padLen

	// Ensure writeBuf is large enough (should always be, but safety check)
	needed := 4 + nonceSize + plaintextLen + c.aead.Overhead()
	if needed > len(c.writeBuf) {
		c.writeBuf = make([]byte, needed)
	}

	// Fill plaintext region: [PayloadLen][Payload][PadLen][Padding]
	pt := c.writeBuf[plaintextStart : plaintextStart+plaintextLen]
	binary.BigEndian.PutUint16(pt[0:2], uint16(len(b)))
	copy(pt[2:], b)
	binary.BigEndian.PutUint16(pt[2+len(b):], uint16(padLen))
	if padLen > 0 {
		// Fill padding with buffered random bytes
		c.randBytes(pt[2+len(b)+2 : 2+len(b)+2+padLen])
	}

	// Generate nonce from buffered random
	c.randBytes(c.nonce)

	// Copy nonce into wire position
	copy(c.writeBuf[4:4+nonceSize], c.nonce)

	// Encrypt in-place: Seal appends ciphertext after nonce in writeBuf
	// We use Seal with dst pointing right after the nonce.
	ciphertext := c.aead.Seal(
		c.writeBuf[4+nonceSize:4+nonceSize], // dst (append to this slice)
		c.nonce,
		pt,
		nil,
	)

	// Write frame header
	frameSize := uint32(nonceSize + len(ciphertext))
	binary.BigEndian.PutUint32(c.writeBuf[0:4], frameSize)

	// Single write syscall for entire frame
	totalLen := 4 + int(frameSize)
	if _, err := c.Conn.Write(c.writeBuf[:totalLen]); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Read implements net.Conn.Read with de-obfuscation.
// It reads a full frame, decrypts it, and extracts the payload.
// Supports internal buffering for payloads larger than the caller's buffer.
func (c *conn) Read(b []byte) (int, error) {
	// Drain leftover from previous frame first
	if len(c.readRest) > 0 {
		n := copy(b, c.readRest)
		c.readRest = c.readRest[n:]
		return n, nil
	}

	// Read frame header (4 bytes) — zero-alloc, uses stack array
	if _, err := io.ReadFull(c.Conn, c.readHdr[:]); err != nil {
		return 0, err
	}
	frameSize := binary.BigEndian.Uint32(c.readHdr[:])

	// Sanity check frame size to prevent OOM
	if frameSize > 2*1024*1024 {
		return 0, fmt.Errorf("obfs: frame too large")
	}

	// Read frame body — reuse readBuf if big enough
	var frame []byte
	if int(frameSize) <= cap(c.readBuf) {
		frame = c.readBuf[:frameSize]
	} else {
		// Frame larger than our buffer — allocate (rare)
		frame = make([]byte, frameSize)
	}
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	nonceSize := c.aead.NonceSize()
	if len(frame) < nonceSize {
		return 0, fmt.Errorf("obfs: invalid frame")
	}

	nonce := frame[:nonceSize]
	ciphertextBytes := frame[nonceSize:]

	// Decrypt in-place to avoid allocation
	plaintext, err := c.aead.Open(ciphertextBytes[:0], nonce, ciphertextBytes, nil)
	if err != nil {
		return 0, fmt.Errorf("obfs: failed to decrypt: %w", err)
	}

	if len(plaintext) < 4 {
		return 0, fmt.Errorf("obfs: invalid plaintext format")
	}

	payloadLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if len(plaintext) < 2+payloadLen+2 {
		return 0, fmt.Errorf("obfs: invalid payload length")
	}

	payload := plaintext[2 : 2+payloadLen]
	copied := copy(b, payload)

	if copied < len(payload) {
		// Buffer remaining data — need a separate copy since payload
		// aliases readBuf which will be overwritten on next Read
		c.readRest = append(c.readRest[:0], payload[copied:]...)
	}

	return copied, nil
}

// SetDeadline overrides net.Conn.SetDeadline
func (c *conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline overrides net.Conn.SetReadDeadline
func (c *conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline overrides net.Conn.SetWriteDeadline
func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
