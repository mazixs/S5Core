package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
	cfg     Config
	aead    cipher.AEAD
	readbuf []byte // internal buffer for partial reads
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

	return &conn{
		Conn: c,
		cfg:  cfg,
		aead: aead,
	}, nil
}

// Write implements net.Conn.Write with obfuscation.
// Protocol: [Payload Length (2 bytes)] [Payload] [Padding Length (2 bytes)] [Padding] -> AES-GCM -> [Nonce (12 bytes)] [Ciphertext]
func (c *conn) Write(b []byte) (int, error) {
	if len(b) > 65535 {
		return 0, fmt.Errorf("obfs: payload too large")
	}

	// Generate random padding
	padLen := 0
	if c.cfg.MaxPadding > 0 {
		padLenBytes := make([]byte, 2)
		// simple random for pad length up to MaxPadding
		_, _ = rand.Read(padLenBytes)
		padLen = int(binary.BigEndian.Uint16(padLenBytes)) % (c.cfg.MaxPadding + 1)
	}

	padding := make([]byte, padLen)
	if padLen > 0 {
		_, _ = rand.Read(padding)
	}

	// Construct plaintext frame: [PayloadLen][Payload][PaddingLen][Padding]
	plaintextLen := 2 + len(b) + 2 + padLen
	plaintext := make([]byte, plaintextLen)

	binary.BigEndian.PutUint16(plaintext[0:2], uint16(len(b)))
	copy(plaintext[2:], b)
	binary.BigEndian.PutUint16(plaintext[2+len(b):], uint16(padLen))
	copy(plaintext[2+len(b)+2:], padding)

	// Encrypt
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, fmt.Errorf("obfs: failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// Send frame size + nonce + ciphertext
	frameSize := uint32(len(nonce) + len(ciphertext))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, frameSize)

	if _, err := c.Conn.Write(append(header, append(nonce, ciphertext...)...)); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Read implements net.Conn.Read with de-obfuscation.
// It reads a full frame, decrypts it, and extracts the payload.
// Supports internal buffering for payloads larger than the caller's buffer.
func (c *conn) Read(b []byte) (int, error) {
	// Drain internal buffer first
	if len(c.readbuf) > 0 {
		n := copy(b, c.readbuf)
		c.readbuf = c.readbuf[n:]
		return n, nil
	}

	// Read frame size
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	frameSize := binary.BigEndian.Uint32(header)

	// Sanity check frame size to prevent OOM
	if frameSize > 2*1024*1024 { // 2MB max frame
		return 0, fmt.Errorf("obfs: frame too large")
	}

	frame := make([]byte, frameSize)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	nonceSize := c.aead.NonceSize()
	if len(frame) < nonceSize {
		return 0, fmt.Errorf("obfs: invalid frame")
	}

	nonce := frame[:nonceSize]
	ciphertext := frame[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
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
		// Buffer remaining data for next Read() call
		c.readbuf = append(c.readbuf[:0], payload[copied:]...)
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
