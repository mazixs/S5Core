package obfs

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// DefaultMTU is the default maximum frame size on the wire.
const DefaultMTU = 1400

// MinMTU is the smallest acceptable MTU. It must accommodate the 2-byte
// masked length, the kind byte and the two 2-byte length fields inside the
// frame, the 16-byte GCM tag, and a payload worth carrying.
const MinMTU = 64

// Role says which end of a connection this is. The two ends must disagree:
// the role separates the nonce space of the two directions, which share one
// key. There is no default, because a wrong default would mean both ends
// encrypting different data under the same key and nonce - the one mistake
// AES-GCM does not survive.
type Role uint8

const (
	// RoleUnset is the zero value and is rejected by NewConn.
	RoleUnset Role = iota
	// RoleClient is the end that dialed.
	RoleClient
	// RoleServer is the end that accepted.
	RoleServer
)

// frameOverhead is what one frame costs besides the bytes it carries: the
// masked length on the wire, the kind byte, the payload and padding length
// fields inside the AEAD, and the GCM tag.
const frameOverhead = 2 + 1 + 2 + 2 + 16

// frameKind is the first byte inside the AEAD. It exists because a tunnel has
// to carry more than a byte stream: the end of one direction, and frames that
// carry nothing at all.
//
// Plan task Ф4-9. A WebSocket connection has no half-close - the close frames
// end it in both directions at once - so "the application closed its side" had
// no way to cross this layer, and the client closed the whole connection
// instead, cutting off a reply the server had not finished sending. The signal
// now lives in the format, one layer above whatever transport is underneath,
// which is what makes direct TCP and WSS behave the same.
//
// The kind is inside the AEAD, so the wire shows a frame of the usual length
// and nothing else: a FIN is the size of a frame this connection has already
// sent, exactly like a keepalive.
type frameKind uint8

const (
	// kindData carries payload. A data frame with an empty payload is what an
	// empty Write produces and is dropped by the reader.
	kindData frameKind = 0
	// kindKeepalive carries nothing and exists to keep the path open.
	kindKeepalive frameKind = 1
	// kindFIN says this direction is over. The peer's Read returns io.EOF
	// after it, while the other direction keeps working.
	kindFIN frameKind = 2
	// kindHello is the client naming its build and transport, once, ahead
	// of its first data frame (plan task Ф5-7). See control.go.
	kindHello frameKind = 3
	// kindAdvice is the server recommending a transport and a traffic shape,
	// once, ahead of its first data frame (plan task Ф5-7). See control.go.
	kindAdvice frameKind = 4
)

// saltSize is the length of the prologue the default scheme puts in front of
// a client's first frame. It is what makes two connections with the same PSK
// look unrelated: keys, nonces and length masks are all derived from it.
//
// Without it, counter nonces under a shared PSK make the first frame of every
// connection byte-identical - a fixed 64-byte prefix, which is exactly what
// the level-2 checklist looks for.
//
// The value belongs to the scheme, not to this layer: a connection asks its
// Scheme how many bytes its prologue takes. The constant remains because the
// write buffer has to be sized before a connection exists.
const saltSize = veil.SaltSize

// minCiphertext is the smallest AEAD blob a well-formed frame can have: the
// kind byte, two length fields and the tag, with neither payload nor padding.
const minCiphertext = 1 + 2 + 2 + 16

// Config holds the configuration for the obfuscation layer.
type Config struct {
	// PSK is the pre-shared key for AES-GCM encryption (must be 32 bytes for AES-256).
	PSK []byte
	// MaxPadding is the maximum random padding length added to each frame.
	MaxPadding int
	// MTU is the maximum transmission unit for obfuscated frames.
	// If zero, DefaultMTU (1400) is used.
	MTU int
	// Role tells this end which half of the nonce space it owns. It has no
	// default: NewConn rejects RoleUnset.
	Role Role

	// PrologueEncoding is how a client's prologue looks on the wire: raw
	// bytes, or base64 with a pad so the connection opens with printable
	// characters. Empty means DefaultPrologueEncoding. It is a sender-side
	// setting only - a server recognises both without being told, because
	// the two cannot be confused (see prologue.go).
	PrologueEncoding PrologueEncoding

	// Scheme is how the prologue in front of a client's first frame becomes
	// the secret both ends derive their keys from. Nil means a veil.Clocked
	// with default windows: the scheme gate G4 chose, with the hour binding
	// task Ф5-3 added. Both ends must agree on it, like they agree on the
	// PSK.
	//
	// It is configurable because plan task Ф5-2 requires the authentication
	// scheme to be replaceable without rewriting the framing around it: this
	// layer knows only the prologue's size and how to turn it into a secret.
	Scheme veil.Scheme

	// History, when set, is the record of session salts this server has
	// already accepted. It belongs to the listener, not to the connection:
	// one history is shared by every connection it accepts, because the
	// replay worth catching is a recorded first frame sent again on a fresh
	// socket, and nothing inside a single connection can see that.
	//
	// A nil history accepts everything, which is what the client side wants:
	// it is the party that picks the salt.
	History *SaltHistory
	// OnFailure, when set, is called once per frame-level failure with its
	// classification. It runs on the reading goroutine and must not block.
	// Nil by default: the obfuscation layer has no opinion about metrics.
	OnFailure FailureObserver
	// OnFrameState, when set, is told what the reader is waiting for each
	// time that changes: the next header, the rest of a frame, or nothing
	// (plan task Ф6-1). It runs on the reading goroutine, once per wait at
	// most, and must not block. Nil by default: the obfuscation layer only
	// reports, the connection's session decides what a state means.
	OnFrameState func(FrameState)

	// KeepaliveMin and KeepaliveMax bound the idle interval after which this
	// end sends a frame that carries nothing, to stop a middlebox on the path
	// from dropping a connection it believes is dead. Zero disables it.
	//
	// The interval is drawn anew for every frame, because a fixed one is a
	// signature: an observer who sees a packet every 45 seconds to the
	// millisecond has identified the protocol without decrypting a byte. It
	// is also suppressed by real traffic - a connection that is being used
	// needs nothing to hold it open - so an idle interval is what is drawn,
	// not a period.
	//
	// Keepalive lives here rather than in the WebSocket transport, where the
	// dead defaultPingInterval constant used to sit, for two reasons: a
	// WebSocket ping is a control frame, distinguishable by opcode and by its
	// size whatever the payload; and the plain obfuscated listener has no
	// WebSocket layer to put it in, while it has the same NAT timeouts.
	KeepaliveMin time.Duration
	KeepaliveMax time.Duration

	// RefuseLinger is how long a server keeps reading, and discarding, a
	// connection whose first frame did not authenticate. Zero closes it at
	// once, which is the historical behaviour and what a client wants.
	//
	// Why a server should not close at once (plan task Ф5-6). A probe that
	// recorded a real client has two things to send: that recording, which
	// decrypts into a complete frame and is refused, and random bytes,
	// whose masked length promises a frame that never arrives. Closing on
	// the first while waiting on the second tells the probe that the bytes
	// it recorded meant something here - the endpoint parses them - which
	// is the one thing the transport exists to hide. Draining makes both
	// end the same way: the connection is held, nothing is said, and the
	// transport's own timeout closes it, exactly as it closes a client that
	// connected and then went quiet.
	//
	// The real bound is usually the listener's handshake timeout, which is
	// stricter and applies to both paths; this is the ceiling for a
	// transport that sets no deadlines of its own.
	RefuseLinger time.Duration

	// Hello, on a client, is sent once ahead of the first data frame, in the
	// same write (plan task Ф5-7). Nil sends nothing. A server ignores it.
	Hello *Hello
	// OnHello, on a server, receives the client's Hello. It runs on the
	// reading goroutine, once per connection at most, and must not block.
	OnHello func(Hello)
	// Advice, on a server, is sent once ahead of the first data frame this
	// end writes, in the same write. Nil sends nothing. A client ignores it.
	Advice *Advice
	// OnAdvice, on a client, receives the server's Advice. It runs on the
	// reading goroutine, once per connection at most, and must not block.
	OnAdvice func(Advice)

	// SplitOpening, on a client, puts the opening in a write of its own
	// ahead of the first frames instead of in the same write. It buys the
	// one exemption the encoded prologue does not: a filter that classifies
	// the first packet may skip packets below a length of its own, and the
	// opening alone is 43-72 bytes where the first write is 125 and up
	// (docs/field/stealth.md, "Второе исключение"). The cost is a short
	// packet at a fixed place in every connection, which is a shape of its
	// own, so this is off by default and a deployment turns it on for a
	// path that needs it. A server ignores it: it never speaks first.
	SplitOpening bool
}

// conn is the obfuscation wrapper around net.Conn.
type conn struct {
	net.Conn
	cfg Config

	// Session state. The two directions have separate keys, derived from the
	// PSK and the connection's salt, so neither the payload cipher nor the
	// length mask is shared between them. sendReady and recvReady say whether
	// the derivation has happened yet: the client derives at setup and sends
	// the salt with its first frame, the server derives when that salt
	// arrives.
	aeadSend cipher.AEAD
	aeadRecv cipher.AEAD
	maskSend veil.LengthMask
	maskRecv veil.LengthMask
	// sendReady is atomic because it is the hand-off between the two
	// directions: on a server the keys are derived by whichever goroutine
	// reads the salt, and the goroutine that writes has to see them. The
	// atomic is what makes that publication legal, not just likely.
	sendReady    atomic.Bool
	recvReady    bool
	prologueSent bool
	// scheme and prologue are the replaceable half of the format: the bytes
	// a client sends ahead of its first frame, and the rule that turns them
	// into the session secret. On a server the slice is filled from the wire.
	scheme   veil.Scheme
	prologue []byte
	// wirePrologue is what a client actually writes ahead of its first
	// frame: the prologue as the configured encoding renders it. On a server
	// it stays nil - the server reads whatever the client chose.
	wirePrologue []byte
	// resolved is what the scheme returned for this connection, from Offer
	// on a client and from Accept on a server. The opening pad is derived
	// from it, so it is kept rather than discarded after key derivation.
	resolved veil.Result
	// offered is what Offer returned. Only a client has it: a server
	// recovers the same values from the prologue through Accept.
	offered veil.Result
	// identity is the member the scheme recognised in the prologue, empty
	// when the scheme has no members (plan task Ф5-5). It is published by
	// Identity() only once a frame has decrypted, not when the prologue
	// resolved: see the comment there.
	identity string
	// authenticated goes true when a frame has opened under the derived
	// keys. Nothing above may act on identity before it does.
	authenticated bool
	// lingered says the refusal drain has already run on this connection.
	lingered bool
	// frameState is what the reader last reported through OnFrameState.
	// Touched under readMu only.
	frameState FrameState

	// pending is the control frame that goes out ahead of this end's first
	// frame; nil once sent. helloSeen and adviceSeen make the receiving side
	// deliver each kind once. All three are touched under the mutex of
	// their direction.
	pending    *pendingControl
	helloSeen  bool
	adviceSeen bool

	// Write and read are serialised separately. net.Conn is documented as
	// safe for concurrent use, and a tunnel always has a reader and a writer
	// on the same connection; the comment that used to stand here claimed the
	// opposite and the buffers below were shared on that basis. One mutex per
	// direction keeps the two independent - a slow write must not hold up a
	// read - which is what the sequence of frames in each direction needs
	// anyway, since counters and mask scratch advance per frame.
	writeMu sync.Mutex
	readMu  sync.Mutex

	// Frame geometry, derived from the MTU once at setup: maxFrame is the
	// largest a frame gets on the wire, payloadBudget is what one frame can
	// carry once the length fields and the tag are paid for, and padCap is
	// the largest padding that still leaves room for payload.
	maxFrame      int
	payloadBudget int
	padCap        int

	// Frame counters. They are what the nonce and the length mask are built
	// from, so they must advance in step on both ends - which TCP guarantees,
	// since it delivers the frames in order.
	writeCounter uint64
	readCounter  uint64

	// Pre-allocated write buffers and scratch, held under writeMu. The mask
	// scratch is per direction: one shared pair of arrays meant a reader and
	// a writer wrote the same 16 bytes at the same time, which is a race
	// whether or not it has yet produced a broken frame.
	writeBuf  []byte   // holds one batch of finished frames
	nonceSend [12]byte // reusable nonce, rebuilt from the counter per frame

	// Buffered random source - the only thing drawn from it now is the
	// padding length, two bytes per frame, so one refill covers 2048 frames.
	randBuf [4096]byte
	randPos int

	// Pre-allocated read buffers. readBuf is a socket buffer, not a frame
	// buffer: readLo..readHi is what has been read from the socket and not
	// yet consumed, which is usually several whole frames plus part of one.
	readBuf   []byte // buffered socket bytes
	readLo    int    // first unconsumed byte
	readHi    int    // one past the last buffered byte
	readRest  []byte // payload of the last frame that did not fit the caller
	restLo    int    // how much of readRest has been handed out
	nonceRecv [12]byte

	// bytesRead counts bytes taken from the underlying connection, to report
	// how much a peer sent before a failure. Read path only, under readMu.
	bytesRead int64
	// failed is set once a failure has been reported, so that one broken
	// connection contributes one event rather than one per retry.
	failed bool

	// replayed records that this connection's salt had been seen before. The
	// refusal is deliberately not issued here - see Read.
	replayed bool

	// Half-close state. writeClosed is set by CloseWrite under writeMu and
	// makes every later Write fail, the way a TCP socket does; readClosed is
	// set by the reader under readMu when a FIN frame arrives. They are
	// separate because that is the whole point of a half-close: one direction
	// ends while the other goes on.
	writeClosed bool
	readClosed  bool

	// Keepalive state. lastWrite is atomic because the keepalive goroutine
	// reads it without holding writeMu - taking the write lock to find out
	// whether a write is in progress would be a way to wait for one. The
	// recent frame sizes, in contrast, are only touched under writeMu, by
	// the writer that records them and by the keepalive that reads them.
	lastWrite   atomic.Int64
	done        chan struct{}
	closeOnce   sync.Once
	recentSizes [16]int
	recentPos   int
	recentLen   int
}

// NewConn wraps an existing net.Conn with obfuscation. cfg.Role must say
// which end this is; NewClientConn and NewServerConn set it for you.
func NewConn(c net.Conn, cfg Config) (net.Conn, error) {
	if len(cfg.PSK) != 32 {
		return nil, fmt.Errorf("obfs: PSK must be 32 bytes")
	}

	if cfg.Role != RoleClient && cfg.Role != RoleServer {
		return nil, fmt.Errorf("obfs: Role must be RoleClient or RoleServer; the two ends share a key and must not share a nonce space")
	}

	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}

	if cfg.MTU <= frameOverhead {
		return nil, fmt.Errorf("obfs: MTU %d leaves no room for a payload, it must exceed %d", cfg.MTU, frameOverhead)
	}
	// What is left of the MTU is shared by payload and padding. The payload
	// length is a 16-bit field, and so is the frame length on the wire, so
	// the share is capped there however large the MTU is.
	budget := cfg.MTU - frameOverhead
	if budget > 65535-(minCiphertext-16) {
		budget = 65535 - (minCiphertext - 16)
	}

	// Padding is drawn per frame out of the same budget. Capping it at half
	// keeps a large MaxPadding from squeezing the payload down to a handful
	// of bytes per frame; with the defaults (256 bytes of padding, MTU 1400)
	// the cap never binds.
	padCap := cfg.MaxPadding
	if padCap > budget/2 {
		padCap = budget / 2
	}

	oc := &conn{
		Conn:          c,
		cfg:           cfg,
		maxFrame:      frameOverhead + budget,
		payloadBudget: budget,
		padCap:        padCap,
		// The salt rides in front of the first batch, and a control frame
		// may ride between the two, so the buffer has to hold the salt
		// plus two whole frames even when a jumbo MTU pushes the batch
		// down to a single frame.
		writeBuf: make([]byte, max(batchBytes(framesPerBatch, frameOverhead+budget, maxWriteBatchBytes), maxWirePrologue+2*(frameOverhead+budget))),
		// The read side buffers whole batches for the same reason the write
		// side sends them: with MTU-sized frames, reading one frame at a
		// time means two syscalls per frame.
		readBuf: make([]byte, batchBytes(readBatchFrames, frameOverhead+budget, maxReadBatchBytes)),
		randPos: 4096, // force fill on first use
		done:    make(chan struct{}),
	}
	oc.markWrite()

	oc.scheme = cfg.Scheme
	if oc.scheme == nil {
		oc.scheme = veil.NewClocked()
	}
	if !cfg.PrologueEncoding.Valid() {
		return nil, fmt.Errorf("obfs: prologue encoding %q is not one of %q or %q", cfg.PrologueEncoding, ProloguePrintable, PrologueRaw)
	}
	if n := oc.scheme.Size(); n != saltSize {
		// The write buffer above was sized for a prologue of saltSize bytes.
		// A scheme that needs a different prologue is a format change, not a
		// configuration option, so say so instead of overrunning the buffer.
		return nil, fmt.Errorf("obfs: scheme %q wants a %d-byte prologue, this framing carries %d", oc.scheme.Name(), n, saltSize)
	}
	oc.prologue = make([]byte, saltSize)

	if cfg.Role == RoleClient {
		// The client picks the prologue and is ready for both directions
		// right away; the prologue itself goes out in front of its first
		// frame. The server has to wait for it, which it does on its first
		// read.
		offered, err := oc.scheme.Offer(cfg.PSK, oc.prologue)
		if err != nil {
			return nil, fmt.Errorf("obfs: failed to draw a session prologue: %w", err)
		}
		oc.offered = offered
		if err := oc.deriveSession(); err != nil {
			return nil, err
		}
		if err := oc.encodeOpening(); err != nil {
			return nil, err
		}
	} else {
		// The server never sends a prologue of its own: there is one per
		// connection and the client picked it. Without this the server's
		// first write would put 32 bytes in front of its first frame - bytes
		// the client does not expect and cannot skip, so every reply desynced
		// the stream, and bytes that were the same on every connection, which
		// is the pattern the prologue exists to remove.
		oc.prologueSent = true
	}

	// What this end says once, ahead of its first frame (plan task Ф5-7).
	// Queued here so that a payload which does not fit the MTU is refused
	// where the configuration is, not on the first write.
	switch {
	case cfg.Role == RoleClient && cfg.Hello != nil:
		if err := oc.queueControl(kindHello, encodeHello(*cfg.Hello)); err != nil {
			return nil, err
		}
	case cfg.Role == RoleServer && cfg.Advice != nil:
		if err := oc.queueControl(kindAdvice, encodeAdvice(*cfg.Advice)); err != nil {
			return nil, err
		}
	}

	oc.startKeepalive()

	return oc, nil
}

// Identity is which member the scheme recognised, empty when the scheme has
// no members or the connection has not proved itself yet.
//
// A resolved identity is already authenticated - the prologue MAC is checked
// under that member's own key, so an observer who copies the identity field
// out of someone else's connection does not get their name. It is
// nevertheless withheld until a frame has decrypted, which raises the
// forgery cost from the prologue's 64-bit tag to the frame's 128-bit one and
// costs the caller nothing: whatever asks who this is has already read from
// the connection.
//
// It is meant to be called from the connection's own read path - the SOCKS5
// handshake that follows - and is not safe to call concurrently with Read.
func (c *conn) Identity() string {
	if !c.authenticated {
		return ""
	}
	return c.identity
}

// resolve asks the scheme what this connection's prologue means: the secret
// to derive from, and the context to derive under. A client already got the
// answer when it drew the prologue.
func (c *conn) resolve() (veil.Result, error) {
	if c.cfg.Role == RoleClient {
		return c.offered, nil
	}
	return c.scheme.Accept(c.cfg.PSK, c.prologue)
}

// deriveSession turns the PSK and the connection's prologue into four keys:
// one AEAD and one length mask per direction. Both ends run it over the same
// prologue and label set, so each derives the pair it sends with and the pair
// it reads with.
//
// The work itself lives in pkg/veil, which owns the scheme and the labels;
// this method only hands it the prologue and unpacks the result. That split
// is what plan task Ф5-2 asks for: replacing the authentication scheme must
// not touch the framing.
//
// The PSK is never used as a key directly. Two directions used to share one
// AES-256 key and one 96-bit nonce space; now they share nothing but the
// secret they are derived from, and a nonce cannot repeat within a direction
// because it is a counter. What this does not buy is forward secrecy: with
// the symmetric scheme, whoever learns the PSK can still derive the keys of a
// recorded session, since the prologue is on the wire. See docs/gates/g4-first-frame.md
// for why that debt was taken on knowingly and what it would cost to repay.
func (c *conn) deriveSession() error {
	resolved, err := c.resolve()
	if err != nil {
		return fmt.Errorf("obfs: key derivation failed: %w", err)
	}

	role := veil.RoleClient
	if c.cfg.Role == RoleServer {
		role = veil.RoleServer
	}
	session, err := veil.Derive(c.cfg.PSK, resolved.Secret, resolved.Context, role)
	if err != nil {
		return fmt.Errorf("obfs: %w", err)
	}

	c.resolved = resolved
	c.identity = resolved.Identity
	c.aeadSend, c.maskSend = session.Send.Data, session.Send.LengthMask
	c.aeadRecv, c.maskRecv = session.Recv.Data, session.Recv.LengthMask
	c.sendReady.Store(true)
	c.recvReady = true
	return nil
}

// encodeOpening renders what a client puts on the wire ahead of its first
// frame. With the raw encoding that is the prologue itself; with the
// printable one it is the prologue in base64 followed by a pad whose length
// both ends derive from the session secret, so the boundary between the
// printable opening and the frames behind it is not at a fixed offset.
func (c *conn) encodeOpening() error {
	if c.encoding() == PrologueRaw {
		c.wirePrologue = c.prologue
		return nil
	}
	pad, err := veil.OpeningPad(c.cfg.PSK, c.resolved.Secret, c.resolved.Context, openingPadMax)
	if err != nil {
		return fmt.Errorf("obfs: %w", err)
	}
	wire := make([]byte, encodedPrologueSize+pad)
	if _, err := encodeWirePrologue(wire, c.prologue, pad); err != nil {
		return err
	}
	c.wirePrologue = wire
	return nil
}

// encoding is the prologue encoding this connection sends under.
func (c *conn) encoding() PrologueEncoding {
	if c.cfg.PrologueEncoding == "" {
		return DefaultPrologueEncoding
	}
	return c.cfg.PrologueEncoding
}

// readOpening consumes a client's opening from the read buffer and leaves the
// prologue in c.prologue. The two encodings are told apart by the first
// saltSize bytes: a raw prologue is uniformly random and falls inside the
// base64 alphabet with probability 2^-64, so a printable opening is the only
// thing that reads as one.
//
// The pad is read after the keys are derived, because its length comes from
// the same secret. That order matters for more than convenience: a server
// that could not derive keys must not behave differently here, and it does
// not - a wrong PSK produces a wrong pad length, the frame behind it fails to
// decrypt, and the connection dies where every other wrong key dies.
// Every refusal here goes through fail, including the three that once
// returned their error directly (review finding R08): the two derivations and
// the opening pad. They are all failures of a scheme, and a scheme is
// replaceable - the ones wired in today answer an unknown client with a wrong
// secret rather than an error, so today none of them can be reached by
// anything a client sends. That is a property of the schemes, not of this
// function, and the moment a scheme returns an error on client data, a
// refusal that skipped fail would close the socket at once while every other
// refusal drains it to the end of the handshake budget. The difference in
// timing is the whole of what Config.RefuseLinger buys (docs/design/decoy.md).
func (c *conn) readOpening() error {
	if err := c.ensure(saltSize, FrameAwaitHeader); err != nil {
		return c.fail(ReasonEOFBeforeFrame, err)
	}
	if !looksEncoded(c.readBuf[c.readLo : c.readLo+saltSize]) {
		copy(c.prologue, c.readBuf[c.readLo:c.readLo+saltSize])
		c.readLo += saltSize
		if err := c.deriveSession(); err != nil {
			return c.fail(ReasonBadOpening, err)
		}
		return nil
	}

	if err := c.ensure(encodedPrologueSize, FrameAwaitHeader); err != nil {
		return c.fail(ReasonEOFBeforeFrame, err)
	}
	if err := decodeWirePrologue(c.prologue, c.readBuf[c.readLo:c.readLo+encodedPrologueSize]); err != nil {
		return c.fail(ReasonShortFrame, err)
	}
	c.readLo += encodedPrologueSize
	if err := c.deriveSession(); err != nil {
		return c.fail(ReasonBadOpening, err)
	}

	pad, err := veil.OpeningPad(c.cfg.PSK, c.resolved.Secret, c.resolved.Context, openingPadMax)
	if err != nil {
		return c.fail(ReasonBadOpening, fmt.Errorf("obfs: %w", err))
	}
	if pad > 0 {
		if err := c.ensure(pad, FrameAwaitHeader); err != nil {
			return c.fail(ReasonEOFBeforeFrame, err)
		}
		c.readLo += pad
	}
	return nil
}

// NewClientConn wraps the dialing end of a connection.
func NewClientConn(c net.Conn, cfg Config) (net.Conn, error) {
	cfg.Role = RoleClient
	return NewConn(c, cfg)
}

// NewServerConn wraps the accepting end of a connection.
func NewServerConn(c net.Conn, cfg Config) (net.Conn, error) {
	cfg.Role = RoleServer
	return NewConn(c, cfg)
}

// frameNonce builds the nonce for one frame. Nothing of it goes on the wire:
// both ends derive it from the direction and the number of frames sent that
// way so far, which is why the 12 bytes that used to precede every frame are
// gone. A counter also removes the birthday bound a random 96-bit nonce has
// under one long-lived PSK.
func frameNonce(scratch *[12]byte, counter uint64) []byte {
	*scratch = [12]byte{}
	binary.BigEndian.PutUint64(scratch[4:], counter)
	return scratch[:]
}

func (c *conn) sendNonce(counter uint64) []byte { return frameNonce(&c.nonceSend, counter) }
func (c *conn) recvNonce(counter uint64) []byte { return frameNonce(&c.nonceRecv, counter) }

// sendMask and recvMask return the two bytes that hide a frame's length.
// They come from a keystream taken over the same (direction, counter) pair
// the nonce uses, under a separate key - in the manner of obfs4, so the wire
// shows no length field to lock onto and no constant byte at a fixed offset.
//
// Which keystream depends on the cipher the connection negotiated (AES or
// ChaCha20, plan task Ф5-5); pkg/veil owns that choice and its state, which
// is why each direction holds its own mask and only its own goroutine
// touches it.
func (c *conn) sendMask(counter uint64) uint16 { return c.maskSend.Mask(counter) }

func (c *conn) recvMask(counter uint64) uint16 { return c.maskRecv.Mask(counter) }

// randBytes fills dst with random bytes from the buffered source.
// This batches crypto/rand syscalls to reduce overhead.
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

// randUint16 returns a random uint16 from the buffered source.
func (c *conn) randUint16() uint16 {
	var b [2]byte
	c.randBytes(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// framesPerBatch is how many finished frames the write buffer holds before it
// goes to the socket. Segmenting by MTU turns one 32 KiB relay write into ~24
// frames; sending each on its own would turn one syscall into 24. Batching
// keeps the syscall count near the old one while the per-connection buffer
// stays around 11 KiB instead of the 65.8 KiB a maximum-sized frame needed.
const framesPerBatch = 16

// readBatchFrames sizes the socket buffer on the receiving side. It is a
// separate number because the two sides are not symmetric: the writer decides
// how much it hands the kernel at once, the reader only decides how much it is
// willing to take in one syscall. Measurement says the reader is the cheaper
// of the two - going past eight frames here bought nothing - so it gets the
// smaller buffer.
const readBatchFrames = 8

// maxWriteBatchBytes and maxReadBatchBytes bound the buffers for a large MTU,
// where the frame count alone would put a jumbo-frame connection back at the
// memory it used before segmenting.
const (
	maxWriteBatchBytes = 32 * 1024
	maxReadBatchBytes  = 16 * 1024
)

// batchBytes is the buffer for frames frames of frameLen bytes, never more
// than limit and never less than one whole frame.
func batchBytes(frames, frameLen, limit int) int {
	size := frames * frameLen
	if size > limit {
		size = (limit / frameLen) * frameLen
	}
	if size < frameLen {
		size = frameLen
	}
	return size
}

// Write implements net.Conn.Write with obfuscation.
// Protocol: [MaskedLen 2B] [AES-GCM([PayloadLen 2B][Payload][PadLen 2B][Padding])]
//
// The caller's buffer is cut into frames that each fit the MTU. Before this,
// a frame was as large as the caller's write - which is 32 KiB from the relay's
// io.CopyBuffer - so the wire carried frames that no network path would ever
// produce, and the length distribution followed the relay's buffer size.
//
// Zero-alloc hot path: all buffers are pre-allocated and reused.
func (c *conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Cut the write into equal parts instead of filling frames to the MTU and
	// leaving a short remainder. The remainder is a shape of its own on the
	// wire - "MTU, MTU, 70 bytes" says the sender had one 32 KiB buffer - and
	// equal parts need the same number of frames.
	target := c.payloadBudget
	if len(b) > c.payloadBudget {
		frames := (len(b) + c.payloadBudget - 1) / c.payloadBudget
		target = (len(b) + frames - 1) / frames
	}

	if !c.sendReady.Load() {
		// Only the server can be here: it has no keys until the client's
		// salt arrives, and this layer never speaks first.
		return 0, errors.New("obfs: cannot write before the peer's session salt has arrived")
	}

	if c.writeClosed {
		return 0, errWriteClosed
	}

	written := 0
	for {
		// flushed is what the peer is known to have been sent once this
		// batch is gone; bytes still in the batch are not counted until
		// the socket has taken them.
		flushed := written
		batch := 0
		if !c.prologueSent {
			c.prologueSent = true
			if c.cfg.SplitOpening {
				// The opening goes out on its own, so what the path sees
				// first is 43-72 bytes and not the whole first write.
				if _, err := c.Conn.Write(c.wirePrologue); err != nil {
					return 0, err
				}
				c.markWrite()
			} else {
				// The salt goes out in the same write as the first frames,
				// so the connection does not open with a packet of its own.
				batch = copy(c.writeBuf, c.wirePrologue)
			}
		}
		// A hello or an advice goes out the same way: ahead of the first
		// data frame, in its write, so it is neither a packet of its own
		// nor a round trip.
		batch += c.flushPendingLocked(c.writeBuf[batch : batch+c.maxFrame])
		for {
			n, taken := c.encodeFrame(c.writeBuf[batch:batch+c.maxFrame], b[written:], target)
			batch += n
			written += taken
			// An empty write still produces one frame, which is what this
			// layer did before and what a caller passing an empty buffer
			// gets from any net.Conn.
			if written >= len(b) || batch+c.maxFrame > len(c.writeBuf) {
				break
			}
		}

		if _, err := c.Conn.Write(c.writeBuf[:batch]); err != nil {
			return flushed, err
		}
		c.markWrite()
		if written >= len(b) {
			return len(b), nil
		}
	}
}

// encodeFrame builds one frame into buf, which must hold a full MTU-sized
// frame, and returns the frame's length on the wire together with the number
// of payload bytes it took from b.
//
// Padding is drawn first and the payload takes what is left of the budget, so
// the frame is at most the MTU whatever the draw was.
func (c *conn) encodeFrame(buf []byte, b []byte, target int) (int, int) {
	padLen := 0
	if c.padCap > 0 {
		padLen = int(c.randUint16()) % (c.padCap + 1)
	}

	take := len(b)
	if take > target {
		take = target
	}
	if take > c.payloadBudget-padLen {
		take = c.payloadBudget - padLen
	}

	plaintextLen := 1 + 2 + take + 2 + padLen

	// Fill plaintext region: [Kind][PayloadLen][Payload][PadLen][Padding]
	pt := buf[2 : 2+plaintextLen]
	pt[0] = byte(kindData)
	binary.BigEndian.PutUint16(pt[1:3], uint16(take))
	copy(pt[3:], b[:take])
	binary.BigEndian.PutUint16(pt[3+take:], uint16(padLen))
	if padLen > 0 {
		// Padding is zeroed, not randomised. It sits inside the AEAD, so the
		// wire carries ciphertext either way and an observer cannot tell the
		// two apart; the only party that ever sees the bytes is the peer that
		// holds the PSK and throws them away. TLS 1.3 pads its records the
		// same way (RFC 8446, section 5.4).
		//
		// It is also what makes segmenting affordable: drawing padding from
		// crypto/rand costs one getrandom per few frames once a write becomes
		// twenty-odd frames instead of one, and that syscall dominated the
		// write path.
		clear(pt[3+take+2:])
	}

	counter := c.writeCounter
	c.writeCounter++

	// Encrypt in place: dst starts exactly where the plaintext does, which is
	// the one overlap crypto/cipher allows.
	ciphertext := c.aeadSend.Seal(buf[2:2], c.sendNonce(counter), pt, nil)

	// The length goes out masked, so the wire has no field an analyser can
	// use to find the next frame boundary.
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ciphertext))^c.sendMask(counter))

	// Remember how long this frame was on the wire. A keepalive copies one of
	// these lengths, which is what "indistinguishable in size from a data
	// frame" means in practice: not a size chosen to look plausible, but a
	// size this connection has actually sent.
	wire := 2 + len(ciphertext)
	c.recentSizes[c.recentPos] = wire
	c.recentPos = (c.recentPos + 1) % len(c.recentSizes)
	if c.recentLen < len(c.recentSizes) {
		c.recentLen++
	}

	return wire, take
}

// buffered reports how many bytes have been read from the socket and not yet
// consumed.
func (c *conn) buffered() int { return c.readHi - c.readLo }

// ensure guarantees that n bytes of the incoming stream are in the buffer,
// reading from the socket as needed.
//
// The buffer is what keeps segmenting affordable on the receiving side: a
// 32 KiB transfer is now twenty-odd frames, and reading each frame straight
// from the socket would be two syscalls per frame. One read usually brings a
// whole batch.
//
// want is the state the reader is in while it waits for these bytes. It is
// reported only when the socket actually has to be read: bytes that are
// already buffered were waited for under the state of the read that brought
// them, and reporting again would invent a wait that never happened.
func (c *conn) ensure(n int, want FrameState) error {
	if c.buffered() >= n {
		return nil
	}
	c.setFrameState(want)

	switch {
	case n > len(c.readBuf):
		// A peer whose frames are larger than ours - an older build, or one
		// configured with a bigger MTU. Grow to what it actually sends, once
		// per connection; the size is bounded by the frame-size check.
		grown := make([]byte, n)
		c.readHi = copy(grown, c.readBuf[c.readLo:c.readHi])
		c.readBuf = grown
		c.readLo = 0
	case c.readLo+n > len(c.readBuf):
		// Room exists, it is just behind the unconsumed bytes.
		c.readHi = copy(c.readBuf, c.readBuf[c.readLo:c.readHi])
		c.readLo = 0
	}

	for c.buffered() < n {
		m, err := c.Conn.Read(c.readBuf[c.readHi:])
		c.readHi += m
		c.bytesRead += int64(m)
		if err != nil {
			// A stream that ends between frames ended cleanly; one that ends
			// inside a frame did not, which is what io.ReadFull used to say
			// when it read the frame itself.
			if errors.Is(err, io.EOF) && c.buffered() > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// Read implements net.Conn.Read with de-obfuscation.
// It takes a full frame from the buffer, decrypts it, and extracts the payload.
// Supports internal buffering for payloads larger than the caller's buffer.
func (c *conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// The loop exists for keepalive frames: they carry no payload and must
	// not surface as a zero-length read, which io.Copy would spin on and a
	// caller reading into a fixed buffer could mistake for a closed stream.
	for {
		n, err := c.readFrame(b)
		if errors.Is(err, errEmptyFrame) {
			continue
		}
		return n, err
	}
}

// errEmptyFrame says the frame just read carried no payload - a keepalive.
// It never leaves the package: Read loops on it.
var errEmptyFrame = errors.New("obfs: frame carries no payload")

// readFrame reads one frame into b. The caller holds readMu.
func (c *conn) readFrame(b []byte) (int, error) {
	// A FIN has already arrived: the stream ended there and nothing after it
	// belongs to the caller. Frames may still be on the socket - the peer's
	// keepalive, for one - and they are not read.
	if c.readClosed && c.restLo >= len(c.readRest) {
		return 0, io.EOF
	}

	// Drain leftover from previous frame first. The buffer is kept whole and
	// an index moves through it: re-slicing it as it drained used to shrink
	// its capacity to nothing, so the append below allocated a new buffer
	// every time - 6 GB of it over a 8 GiB transfer, most of the read path's
	// allocations.
	if c.restLo < len(c.readRest) {
		n := copy(b, c.readRest[c.restLo:])
		c.restLo += n
		return n, nil
	}

	if !c.recvReady {
		if err := c.readOpening(); err != nil {
			return 0, err
		}
		if !c.cfg.History.Accept(c.prologue) {
			// Do not refuse yet. Refusing at the salt would answer a replay
			// before the first frame has even arrived, while a wrong PSK is
			// answered a whole frame later - and that difference in timing is
			// precisely what an active prober measures. The connection is
			// marked instead and goes on to read and decrypt the frame like
			// any other; the refusal comes below, at the point where a bad
			// tag would have produced one.
			c.replayed = true
		}
	}

	if err := c.ensure(2, FrameAwaitHeader); err != nil {
		return 0, c.fail(ReasonEOFBeforeFrame, err)
	}
	counter := c.readCounter
	masked := binary.BigEndian.Uint16(c.readBuf[c.readLo : c.readLo+2])
	frameSize := int(masked ^ c.recvMask(counter))

	// A length below the minimum cannot come from this format. It is the
	// cheapest place to notice a scanner: the two bytes it sent unmask to
	// something arbitrary, and one frame in 300-odd survives this check only
	// to fail the AEAD a moment later.
	if frameSize < minCiphertext {
		return 0, c.fail(ReasonShortFrame, fmt.Errorf("frame shorter than the format allows: %d", frameSize))
	}

	if err := c.ensure(2+frameSize, FrameAwaitBody); err != nil {
		return 0, c.fail(ReasonEOFBeforeFrame, err)
	}
	frame := c.readBuf[c.readLo+2 : c.readLo+2+frameSize]
	c.readLo += 2 + frameSize
	if c.buffered() == 0 {
		// Nothing pending: start the next batch at the front of the buffer
		// so that a steady stream never needs the shifting branch above.
		c.readLo, c.readHi = 0, 0
	}
	c.readCounter++

	// Decrypt in-place to avoid allocation. The plaintext is shorter than the
	// ciphertext it replaces, so this never reaches the frames behind it.
	plaintext, err := c.aeadRecv.Open(frame[:0], c.recvNonce(counter), frame, nil)
	if err != nil {
		return 0, c.fail(ReasonDecryptFail, err)
	}
	// The frame is authentic, so these bytes were produced by someone holding
	// the PSK - but the salt says they were produced once before and recorded.
	// Failing here rather than at the salt costs one decryption and buys the
	// property that matters: a prober replaying a captured handshake sees the
	// same silence, after the same delay, as one sending a frame with a
	// corrupted tag.
	//
	// The connection is not marked authenticated until this check has
	// passed: whoever is sending a recording is precisely the party that
	// does not hold the key, and marking it first would exempt them from
	// the refusal drain (plan task Ф5-6).
	if c.replayed {
		return 0, c.fail(ReasonReplay, errors.New("session salt has been used before"))
	}
	c.authenticated = true
	// The frame is whole and authentic: whatever the reader does next, it is
	// no longer waiting on the wire for this one.
	c.setFrameState(FrameDelivered)

	if len(plaintext) < 5 {
		return 0, c.fail(ReasonShortFrame, fmt.Errorf("plaintext shorter than header: %d", len(plaintext)))
	}

	kind := frameKind(plaintext[0])
	payloadLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if len(plaintext) < 3+payloadLen+2 {
		return 0, c.fail(ReasonShortFrame, fmt.Errorf("declared payload %d exceeds plaintext %d", payloadLen, len(plaintext)))
	}

	switch kind {
	case kindData:
	case kindKeepalive:
		// It went through the same decryption, counter and padding path as
		// any frame, so nothing about it reached the wire differently; here
		// it simply ends.
		return 0, errEmptyFrame
	case kindFIN:
		// The peer has closed its half. Everything it sent before this frame
		// has already been handed to the caller, so this is a clean end of
		// stream and not a failure: io.Copy stops, and this side can still
		// write until it closes its own half.
		c.readClosed = true
		return 0, io.EOF
	case kindHello, kindAdvice:
		// Delivered to the callback and gone: the reader above never sees
		// it, like a keepalive. A payload this build cannot parse is a peer
		// speaking a different encoding, and that is a failure of the same
		// class as an unknown kind.
		if err := c.deliverControl(kind, plaintext[3:3+payloadLen]); err != nil {
			return 0, c.fail(ReasonBadControl, err)
		}
		return 0, errEmptyFrame
	default:
		// The frame authenticated, so it came from a peer holding the PSK -
		// a version of this format that knows a kind this one does not.
		// Guessing is not an option: an unknown kind may carry a payload
		// that means something else entirely.
		return 0, c.fail(ReasonUnknownFrameKind, fmt.Errorf("frame kind %d is not part of this format version", kind))
	}

	if payloadLen == 0 {
		// An empty Write. It produced a frame because every Write does, but
		// there is nothing to hand up, and a zero-length read is what a
		// caller reading into a fixed buffer mistakes for a closed stream.
		return 0, errEmptyFrame
	}

	payload := plaintext[3 : 3+payloadLen]
	copied := copy(b, payload)

	if copied < len(payload) {
		// Buffer remaining data - need a separate copy since payload
		// aliases readBuf which will be overwritten on next Read
		c.readRest = append(c.readRest[:0], payload[copied:]...)
		c.restLo = 0
	}

	return copied, nil
}

// fail classifies a frame-level failure, reports it once per connection to the
// observer and returns it as an error. Reporting once is deliberate: a probe
// that keeps a socket open must not be able to inflate the counters at will.
//
// A clean io.EOF is returned unwrapped. io.Copy compares against io.EOF with
// ==, not errors.Is, so wrapping it would turn every normal end-of-stream into
// a relay error. The event is still observed - only the error value is left
// alone.
func (c *conn) fail(reason FailureReason, cause error) error {
	// A stream that ends between frames was not refused, it ended; every
	// other failure is a frame the reader would not accept.
	if !errors.Is(cause, io.EOF) {
		c.setFrameState(FrameRefused)
	}
	if !c.failed {
		c.failed = true
		if c.cfg.OnFailure != nil {
			c.cfg.OnFailure(&FrameError{Reason: reason, BytesBefore: c.bytesRead, Err: cause})
		}
	}
	c.lingerAfterRefusal()
	if errors.Is(cause, io.EOF) {
		return cause
	}
	return &FrameError{Reason: reason, BytesBefore: c.bytesRead, Err: cause}
}

// lingerAfterRefusal holds a connection that never authenticated, reading
// and discarding whatever else arrives, so that the moment of closing says
// nothing about why it was refused. See Config.RefuseLinger.
//
// It runs on the reading goroutine, which is the goroutine that was about to
// return an error and have its caller close the connection, so nothing else
// is waiting on it. A peer that already authenticated is never drained: it
// holds the key, and there is nothing to hide from it.
func (c *conn) lingerAfterRefusal() {
	if c.cfg.Role != RoleServer || c.authenticated || c.cfg.RefuseLinger <= 0 {
		return
	}
	// Once is enough: a second failure on a connection already being
	// drained would double the budget and let a probe hold a slot for as
	// long as it keeps sending.
	if c.lingered {
		return
	}
	c.lingered = true

	deadline := time.Now().Add(c.cfg.RefuseLinger)
	_ = c.Conn.SetReadDeadline(deadline)
	buf := make([]byte, lingerBufferSize)
	for time.Now().Before(deadline) {
		if _, err := c.Conn.Read(buf); err != nil {
			return
		}
	}
}

// lingerBufferSize is the scratch buffer a drained connection reads into.
// Small on purpose: the frame buffers are what a connection costs, and a
// connection being drained has no use for them.
const lingerBufferSize = 512

// errWriteClosed is what a Write after CloseWrite returns. A TCP socket
// answers with EPIPE there; the value matters less than the fact that the
// caller is told rather than having the bytes silently dropped.
var errWriteClosed = errors.New("obfs: write half of the connection is closed")

// CloseWrite ends this direction by sending a FIN frame, and leaves the other
// one alone.
//
// It does not pass the half-close down to the transport. That is deliberate:
// a TCP socket underneath could carry a real FIN and a WebSocket could not,
// so the two transports would end a stream in two different ways and only one
// of them would work. The frame is the signal on both, and the transport
// underneath stays open until Close.
func (c *conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeClosed {
		return nil
	}
	if !c.sendReady.Load() {
		// A server that has not yet seen the client's salt has no keys to
		// send a frame with. There is nothing this side has sent that the
		// peer is waiting for the end of, so the connection is simply left
		// to Close.
		c.writeClosed = true
		return errors.New("obfs: cannot close the write half before the peer's session salt has arrived")
	}
	c.writeClosed = true
	return c.writeControlLocked(kindFIN)
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

// Identified is a connection whose peer the obfuscation layer recognised by
// name. The obfuscated connections this package returns implement it; the
// name is empty unless the configured scheme has a notion of members.
//
// It exists so that the layers above - the SOCKS5 handshake, quotas,
// logging - can ask who is calling without knowing anything about schemes
// or prologues (plan task Ф5-5).
type Identified interface {
	net.Conn
	Identity() string
}

// IdentityOf is the name the obfuscation layer put on a connection, or the
// empty string for a connection it did not recognise or does not own.
//
// By the time a connection reaches the SOCKS5 layer it has usually been
// wrapped again - metrics, connection limits, deadlines - so the tunnel is
// no longer the outermost thing. Rather than make every wrapper forward an
// Identity method it knows nothing about, this walks down the usual
// unwrapping methods until it finds the tunnel or runs out of layers.
//
// The walk is bounded: a wrapper that returns itself, or a cycle of them,
// would otherwise hang the handshake.
func IdentityOf(c net.Conn) string {
	for range maxConnWrappers {
		if c == nil {
			return ""
		}
		if id, ok := c.(Identified); ok {
			return id.Identity()
		}
		next, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			unwrapper, ok := c.(interface{ Unwrap() net.Conn })
			if !ok {
				return ""
			}
			c = unwrapper.Unwrap()
			continue
		}
		c = next.NetConn()
	}
	return ""
}

// maxConnWrappers bounds the unwrapping walk. Three is what the server
// stacks today; ten leaves room without letting a cycle run forever.
const maxConnWrappers = 10
