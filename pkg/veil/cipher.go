package veil

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// Plan task Ф5-5. AES-GCM is the fastest thing available on a processor with
// AES instructions and one of the slowest without them, because a software
// AES is both slow and, in the table-driven form, hard to keep constant-time.
// The machines that run a client are frequently the second kind: a router on
// aarch64 without the crypto extensions, an older ARM board, a low-end VPS.
//
// So the cipher is not a constant. The client picks what its own processor is
// good at, the server accepts either, and which one was picked never reaches
// the wire: it is part of the context (section 4.3 of docs/veil-spec.md),
// stamped into the prologue MAC, so the server recognises the choice in one
// HMAC rather than by trying to decrypt twice.

// Cipher names an AEAD and its matching length mask.
type Cipher string

const (
	// CipherAES is AES-256-GCM with an AES-ECB length mask: the default,
	// and the right choice wherever AES instructions exist.
	CipherAES Cipher = "aes"
	// CipherChaCha is ChaCha20-Poly1305 with a ChaCha20 length mask. Same
	// key size, same nonce size, same 16-byte tag, so the frame on the wire
	// is byte-for-byte the same shape either way.
	CipherChaCha Cipher = "chacha"
)

// DefaultCipher is what an unset Cipher means.
const DefaultCipher = CipherAES

// Ciphers is every cipher a server should be prepared to accept, most
// preferred first. It is not what a client picks - see PreferredCipher.
func Ciphers() []Cipher { return []Cipher{CipherAES, CipherChaCha} }

// IsCipher reports whether a name is one this build implements. A caller
// that takes the name from configuration should ask before a connection
// needs it, so that a typo is a startup error rather than a tunnel that
// refuses every connection.
func IsCipher(c Cipher) bool {
	for _, known := range Ciphers() {
		if c == known {
			return true
		}
	}
	return c == ""
}

// hasHardwareAES reports whether this processor implements AES in hardware.
// Without it, crypto/aes falls back to a software implementation that is
// several times slower than ChaCha20 and, on most platforms, table-driven.
var hasHardwareAES = cpu.X86.HasAES || cpu.ARM64.HasAES || cpu.S390X.HasAES || cpu.PPC64.IsPOWER8

// PreferredCipher is what this machine should ask for. A client calls it; a
// server has no use for it, because a server takes whatever the client
// chose.
func PreferredCipher() Cipher {
	if hasHardwareAES {
		return CipherAES
	}
	return CipherChaCha
}

// LengthMask produces the two bytes that hide a frame's length.
//
// It is stateful and NOT safe for concurrent use: each direction of a
// connection owns one, and each direction has one writer. That is what lets
// it keep a cipher across frames instead of rebuilding one per frame.
type LengthMask interface {
	Mask(counter uint64) uint16
}

// newAEAD builds the payload cipher for a key.
func newAEAD(c Cipher, key []byte) (cipher.AEAD, error) {
	switch c {
	case CipherChaCha:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("veil: failed to create ChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	case CipherAES, "":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("veil: failed to create cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("veil: failed to create GCM: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("veil: unknown cipher %q", c)
	}
}

// newLengthMask builds the length mask for a key. It runs on a key of its
// own so that the bytes hiding the frame boundary are not the cipher
// protecting the payload.
func newLengthMask(c Cipher, key []byte) (LengthMask, error) {
	switch c {
	case CipherChaCha:
		m := &chachaMask{}
		copy(m.key[:], key)
		return m, nil
	case CipherAES, "":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("veil: failed to create length mask: %w", err)
		}
		return &aesMask{block: block}, nil
	default:
		return nil, fmt.Errorf("veil: unknown cipher %q", c)
	}
}

// aesMask is one AES block per frame: encrypt the counter, take two bytes.
type aesMask struct {
	block cipher.Block
	in    [aes.BlockSize]byte
	out   [aes.BlockSize]byte
}

func (m *aesMask) Mask(counter uint64) uint16 {
	m.in = [aes.BlockSize]byte{}
	binary.BigEndian.PutUint64(m.in[8:], counter)
	m.block.Encrypt(m.out[:], m.in[:])
	return binary.BigEndian.Uint16(m.out[:2])
}

// chachaMask takes its two bytes from the ChaCha20 keystream at the offset
// the frame counter names.
//
// A ChaCha20 keystream block is 64 bytes, which is 32 masks. Producing one
// block per mask would cost more than the payload cipher saves on a machine
// without AES instructions, so a block is produced once and the next 31
// masks are read out of it. Counters within one direction only ever go
// forward, so in practice the block is produced once per 32 frames.
//
// The block counter is 32 bits, so one nonce covers 2^37 frames - about 50 PB
// at the default MTU. The high bits go into the nonce, so the keystream
// never repeats.
type chachaMask struct {
	key    [chacha20.KeySize]byte
	cipher *chacha20.Cipher
	// nonceHigh is which nonce cipher was built with, block is which
	// keystream block buf holds. Both are meaningless until built.
	nonceHigh uint64
	block     uint64
	built     bool
	buf       [chachaBlockSize]byte
}

const (
	chachaBlockSize     = 64
	chachaMasksPerBlock = chachaBlockSize / 2
)

func (m *chachaMask) Mask(counter uint64) uint16 {
	block := counter / chachaMasksPerBlock
	high := block >> 32

	// A cipher is rebuilt when the nonce changes, and also when the counter
	// goes backwards: chacha20.SetCounter refuses to rewind, to keep a
	// caller from reusing a keystream by accident. Nothing here reuses one -
	// the mask is a function of its counter and may be asked for any of
	// them - so the rewind is spelled out as a fresh cipher.
	if !m.built || high != m.nonceHigh || block < m.block {
		var nonce [chacha20.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], high)
		c, err := chacha20.NewUnauthenticatedCipher(m.key[:], nonce[:])
		if err != nil {
			// Unreachable: the key is 32 bytes and the nonce is 12, both
			// fixed by the types above. Masking a length with zeroes
			// silently would be worse than stopping here.
			panic("veil: chacha20 length mask: " + err.Error())
		}
		m.cipher, m.nonceHigh, m.built = c, high, true
		m.fill(block)
	} else if block != m.block {
		m.fill(block)
	}

	return binary.BigEndian.Uint16(m.buf[counter%chachaMasksPerBlock*2:])
}

// fill loads one keystream block into buf.
func (m *chachaMask) fill(block uint64) {
	m.cipher.SetCounter(uint32(block))
	m.buf = [chachaBlockSize]byte{}
	m.cipher.XORKeyStream(m.buf[:], m.buf[:])
	m.block = block
}
