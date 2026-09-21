package veil

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Plan task Ф5-5, second half: identify the user from the first frame in
// time that does not depend on how many users there are.
//
// What it replaces. Today a user proves who they are with a password inside
// the tunnel, and the server verifies it with Argon2id - deliberately
// expensive, which is right for a login form and wrong for every connection
// a browser opens. Worse, it is the wrong shape: the server cannot know who
// is calling until after the SOCKS5 handshake, so per-user keys, per-user
// quotas and per-user revocation all sit behind a password check on the hot
// path.
//
// What this does instead. Every member gets a key of their own. The client
// stamps a per-epoch tag of that key into the prologue, masked so it looks
// like the random bytes around it; the server unmasks it with the shared
// PSK, looks it up in a table, and knows who is calling before the first
// frame is decrypted. The table is rebuilt once an epoch in the background,
// so the lookup is one map read - the same work for ten users and for ten
// thousand. Argon2id stays where it belongs: the control panel.
//
// The construction is Shadowsocks 2022's extended identity header: an
// identity encrypted under the deployment-wide key, so that the server can
// recover it without trying every user, and a per-connection mask, so that
// the same user does not put the same bytes on the wire twice.
//
// What it does not hide: someone who holds the deployment's PSK - that is,
// any member - can unmask the identity field of anyone else's connection
// and tell which member it belongs to. Members are not anonymous to each
// other. They already share the PSK that makes the whole deployment
// invisible, and separating those two secrets would cost a second field on
// the wire.

// Member is one user as the tunnel authenticates them, before SOCKS5 and
// before any password.
type Member struct {
	// ID is what the rest of the server calls this user. It never reaches
	// the wire.
	ID string
	// Key is this member's own secret, 32 bytes. It is not a password and
	// not derived from one: it is drawn at random when the account is
	// created, so nothing on this path is guessable by dictionary.
	Key []byte
}

// MemberKeySize is how long a Member.Key must be.
const MemberKeySize = 32

const (
	// rosterIdentitySize is the masked identity field, between the random
	// bytes and the MAC. Eight bytes: a 2^-64 chance that two members
	// collide in one epoch, checked when the table is built rather than
	// left to chance.
	rosterIdentitySize = 8
	// rosterRandomSize is what is left for randomness. Sixteen bytes still
	// makes a repeated prologue a 2^64 event, which the replay history
	// would catch anyway.
	rosterRandomSize = SaltSize - rosterIdentitySize - clockedTagSize
	// rosterMaskLabel derives the per-connection mask from the shared PSK.
	rosterMaskLabel = "S5Core/veil v1 identity"
	// rosterTagLabel derives a member's per-epoch tag from their own key.
	rosterTagLabel = "S5Core/veil v1 user"
)

// Roster is the clocked scheme with per-member keys: the same hour, the same
// context, the same 32 bytes on the wire, plus an identity the server can
// resolve in constant time.
//
// A client sets Member. A server sets Members. Everything else - the epoch
// window, the contexts, the clock-skew diagnostic - is Clocked's and behaves
// exactly as it does there.
//
//	Prologue = Random(16) || Identity(8) || MAC(8)
//	Identity = Tag(member, epoch) XOR Mask(PSK, Random, epoch)
//	MAC      = HMAC(member key, label || Random || Identity || epoch || context)
//	Secret   = Prologue || epoch || member key
//
// The member's key is in the secret, so two members derive different session
// keys from the same PSK, and neither can read the other's traffic.
type Roster struct {
	Clocked

	// Member is this client's identity. A server leaves it zero.
	Member Member
	// Members is the table a server resolves identities against. A client
	// leaves it nil.
	Members *Directory
	// Anonymous, when set, is the scheme a server falls back to for a
	// prologue that resolves to no member: the deployment's shared account,
	// the clients that have not been given a key of their own yet.
	//
	// It is what makes the move to per-member keys a migration rather than
	// a flag day (plan task Ф5-7). It costs one HMAC on connections that
	// are not members, and nothing on connections that are. Leaving it nil
	// means only members may connect.
	Anonymous *Clocked

	// unresolved is the stand-in key for a prologue that named no member.
	// It is drawn once, at random, and never leaves the process: what it
	// has to be is a key no peer can hold. Without it the refusal secret
	// would be the prologue and the epoch alone - exactly what a client of
	// the shared account derives - and a server with a roster and no
	// fallback would accept every one of them.
	unresolvedOnce sync.Once
	unresolved     []byte
}

func (r *Roster) unresolvedKey() []byte {
	r.unresolvedOnce.Do(func() {
		r.unresolved = make([]byte, MemberKeySize)
		if _, err := rand.Read(r.unresolved); err != nil {
			// Unreachable on any supported platform, and the alternative
			// is a predictable refusal secret, which is the bug this
			// field exists to prevent.
			panic("veil: cannot draw the roster's refusal key: " + err.Error())
		}
	})
	return r.unresolved
}

func (*Roster) Name() string { return "roster" }

// Offer draws the random half, stamps this member's identity and the current
// epoch into it, and returns the secret for that pair.
func (r *Roster) Offer(psk, dst []byte) (Result, error) {
	if len(dst) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue buffer is %d bytes, the roster scheme needs %d", len(dst), SaltSize)
	}
	if len(r.Member.Key) != MemberKeySize {
		return Result{}, fmt.Errorf("veil: member %q has a %d-byte key, the roster scheme needs %d",
			r.Member.ID, len(r.Member.Key), MemberKeySize)
	}
	if _, err := (Symmetric{}).Offer(psk, dst); err != nil {
		return Result{}, err
	}

	epoch := r.epoch()
	random := dst[:rosterRandomSize]
	identity := dst[rosterRandomSize : rosterRandomSize+rosterIdentitySize]

	tag := memberTag(r.Member.Key, epoch)
	mask := identityMask(psk, random, epoch)
	subtle.XORBytes(identity, tag[:], mask[:])

	mac := rosterMAC(r.Member.Key, dst[:rosterRandomSize+rosterIdentitySize], epoch, r.Context)
	copy(dst[rosterRandomSize+rosterIdentitySize:], mac[:clockedTagSize])

	return Result{
		Secret:   rosterSecret(dst, epoch, r.Member.Key),
		Context:  r.Context.normalized(),
		Identity: r.Member.ID,
	}, nil
}

// Accept resolves the member, then checks the MAC under that member's key.
//
// The cost is one HMAC per epoch tried plus one map read - nothing in it
// grows with the number of members. When nothing resolves, it returns a
// secret the peer cannot have derived, for the reason Clocked.Accept gives:
// a prologue that is refused here would be refused faster than a wrong
// payload, and that gap is what an active probe measures.
func (r *Roster) Accept(psk, prologue []byte) (Result, error) {
	if len(prologue) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue is %d bytes, the roster scheme needs %d", len(prologue), SaltSize)
	}
	if r.Members == nil {
		return Result{}, fmt.Errorf("veil: the roster scheme needs a directory of members to accept with")
	}

	mine := r.epoch()
	if member, epoch, ctx, ok := r.search(psk, prologue, mine, r.window()); ok {
		return Result{
			Secret:   rosterSecret(prologue, epoch, member.Key),
			Context:  ctx.normalized(),
			Identity: member.ID,
		}, nil
	}

	if r.Anonymous != nil {
		// Not a member. It may still be a client of the shared account,
		// whose prologue has no identity field at all - the two layouts are
		// the same 32 bytes, so the only way to tell is to try.
		return r.Anonymous.Accept(psk, prologue)
	}

	r.diagnoseRoster(psk, prologue, mine)
	return Result{Secret: rosterSecret(prologue, mine, r.unresolvedKey()), Context: r.Context.normalized()}, nil
}

// search walks the epochs nearest first. Per epoch it is one HMAC for the
// mask, one map read, and one HMAC per accepted context - so the ordinary
// case, a member whose clock is right, costs two HMACs whatever the size of
// the directory.
func (r *Roster) search(psk, prologue []byte, mine int64, window int) (Member, int64, Context, bool) {
	random := prologue[:rosterRandomSize]
	identity := prologue[rosterRandomSize : rosterRandomSize+rosterIdentitySize]
	mac := prologue[rosterRandomSize+rosterIdentitySize:]
	contexts := r.accepts()

	for d := 0; d <= window; d++ {
		for _, epoch := range [2]int64{mine - int64(d), mine + int64(d)} {
			mask := identityMask(psk, random, epoch)
			var tag [rosterIdentitySize]byte
			subtle.XORBytes(tag[:], identity, mask[:])

			if member, ok := r.Members.lookup(epoch, tag); ok {
				for _, ctx := range contexts {
					want := rosterMAC(member.Key, prologue[:rosterRandomSize+rosterIdentitySize], epoch, ctx)
					if hmac.Equal(mac, want[:clockedTagSize]) {
						return member, epoch, ctx, true
					}
				}
			}
			if d == 0 {
				break // -0 and +0 are the same epoch
			}
		}
	}
	return Member{}, 0, Context{}, false
}

// diagnoseRoster is Clocked.diagnose for this layout: it looks further out
// than the accepting window only to tell a skewed clock from a scanner, and
// changes no decision. The rate limit is Clocked's, and for the same reason.
func (r *Roster) diagnoseRoster(psk, prologue []byte, mine int64) {
	if r.OnClockSkew == nil || r.DiagnosticWindow < 0 {
		return
	}
	wide := r.DiagnosticWindow
	if wide == 0 {
		wide = DefaultDiagnosticWindow
	}
	if wide <= r.window() {
		return
	}
	now := r.now().UnixNano()
	last := r.lastDiagnostic.Load()
	if now-last < int64(diagnosticInterval) || !r.lastDiagnostic.CompareAndSwap(last, now) {
		return
	}
	if _, epoch, _, ok := r.search(psk, prologue, mine, wide); ok {
		r.OnClockSkew(epoch - mine)
	}
}

// Directory is the table that turns an identity field into a member.
//
// It holds one map per epoch in the accepting window, rebuilt as the window
// moves. A lookup is one read-locked map read; building is one HMAC per
// member per epoch and happens off the connection path.
//
// It is safe for concurrent use.
type Directory struct {
	// Now is the clock, injectable for tests. Nil means time.Now.
	Now func() time.Time
	// Window is how many epochs either side of the current one to keep
	// ready. Zero means DefaultEpochWindow. It must be at least the window
	// of the scheme that reads it, or a member with a skewed clock is
	// looked up in a table that was never built.
	Window int

	mu      sync.RWMutex
	members []Member
	epochs  map[int64]map[[rosterIdentitySize]byte]Member
}

// NewDirectory builds a directory over the given members and fills the
// table for the current window, so the first connection does not pay for it.
func NewDirectory(members []Member) (*Directory, error) {
	d := &Directory{}
	if err := d.SetMembers(members); err != nil {
		return nil, err
	}
	d.Refresh()
	return d, nil
}

// SetMembers replaces the membership - what a reload of the user file does.
// The tables are rebuilt immediately, so a revoked member stops being
// resolvable at once rather than at the next epoch.
func (d *Directory) SetMembers(members []Member) error {
	for _, m := range members {
		if len(m.Key) != MemberKeySize {
			return fmt.Errorf("veil: member %q has a %d-byte key, need %d", m.ID, len(m.Key), MemberKeySize)
		}
	}
	// Copied: the caller may be holding the slice it just parsed.
	own := make([]Member, len(members))
	copy(own, members)

	d.mu.Lock()
	d.members = own
	d.epochs = nil
	d.mu.Unlock()

	d.Refresh()
	return nil
}

// Len is how many members the directory holds.
func (d *Directory) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.members)
}

func (d *Directory) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Directory) window() int {
	if d.Window <= 0 {
		return DefaultEpochWindow
	}
	return d.Window
}

// Refresh builds the tables for the epochs around now and drops the ones
// that have fallen out of the window. It is idempotent and safe to call as
// often as convenient.
func (d *Directory) Refresh() {
	mine := d.now().Unix() / EpochSeconds
	window := int64(d.window())

	d.mu.Lock()
	defer d.mu.Unlock()
	fresh := make(map[int64]map[[rosterIdentitySize]byte]Member, 2*window+1)
	for epoch := mine - window; epoch <= mine+window; epoch++ {
		if have, ok := d.epochs[epoch]; ok {
			fresh[epoch] = have // already built, and members have not changed
			continue
		}
		fresh[epoch] = d.buildLocked(epoch)
	}
	d.epochs = fresh
}

// Run keeps the tables current until ctx is done. A server starts one of
// these per directory; without it the tables are still correct, because a
// lookup builds a missing epoch itself - but that build is the one thing
// here whose cost grows with the number of members, and it belongs off the
// connection path.
func (d *Directory) Run(ctx context.Context) {
	// Four times an epoch: often enough that the boundary is always
	// crossed by this loop rather than by a connection, rare enough to be
	// invisible. A whole rebuild is skipped when nothing has moved.
	ticker := time.NewTicker(EpochSeconds * time.Second / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.Refresh()
		}
	}
}

// lookup resolves an unmasked tag for one epoch.
func (d *Directory) lookup(epoch int64, tag [rosterIdentitySize]byte) (Member, bool) {
	d.mu.RLock()
	table, ok := d.epochs[epoch]
	if ok {
		member, found := table[tag]
		d.mu.RUnlock()
		return member, found
	}
	d.mu.RUnlock()

	// The epoch is not built: the window moved and Run has not caught up,
	// or nothing is running it. Build it here rather than refuse a member
	// whose clock is fine. This is the only path whose cost depends on the
	// number of members, and it happens at most once per epoch.
	d.mu.Lock()
	if d.epochs == nil {
		d.epochs = make(map[int64]map[[rosterIdentitySize]byte]Member, 1)
	}
	table, ok = d.epochs[epoch]
	if !ok {
		table = d.buildLocked(epoch)
		d.epochs[epoch] = table
	}
	d.mu.Unlock()

	member, found := table[tag]
	return member, found
}

// buildLocked computes one epoch's table. The caller holds the lock.
func (d *Directory) buildLocked(epoch int64) map[[rosterIdentitySize]byte]Member {
	table := make(map[[rosterIdentitySize]byte]Member, len(d.members))
	for _, m := range d.members {
		table[memberTag(m.Key, epoch)] = m
	}
	return table
}

// Collisions reports members that share an identity tag in any epoch of the
// current window - two accounts that would resolve to one. At eight bytes
// this is a 2^-64 event per pair, so the honest answer is that it never
// happens; it is checked rather than assumed because the consequence is one
// member's traffic being billed and routed as another's.
func (d *Directory) Collisions() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var clashes []string
	for epoch, table := range d.epochs {
		if len(table) == len(d.members) {
			continue
		}
		seen := make(map[[rosterIdentitySize]byte]string, len(d.members))
		for _, m := range d.members {
			tag := memberTag(m.Key, epoch)
			if other, dup := seen[tag]; dup {
				clashes = append(clashes, fmt.Sprintf("%q and %q share an identity tag in epoch %d", other, m.ID, epoch))
			}
			seen[tag] = m.ID
		}
	}
	return clashes
}

// memberTag is what a member looks like in one epoch: a value derived from
// their own key alone, so the server can tabulate it ahead of time.
func memberTag(key []byte, epoch int64) [rosterIdentitySize]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(rosterTagLabel))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(epoch))
	mac.Write(buf[:])
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	var tag [rosterIdentitySize]byte
	copy(tag[:], sum[:])
	return tag
}

// identityMask is what hides the tag on the wire. It comes from the
// deployment's PSK and this connection's random bytes, so the same member
// puts different bytes there every time, and only someone who has the PSK
// can strip it.
func identityMask(psk, random []byte, epoch int64) [rosterIdentitySize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(rosterMaskLabel))
	mac.Write(random)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(epoch))
	mac.Write(buf[:])
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	var mask [rosterIdentitySize]byte
	copy(mask[:], sum[:])
	return mask
}

// rosterMAC authenticates the prologue under the member's own key, so
// resolving an identity is not the same as believing it: an observer who
// copies someone's identity field still cannot produce this.
func rosterMAC(key, head []byte, epoch int64, ctx Context) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(clockedMACLabel))
	mac.Write(head)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(epoch))
	mac.Write(buf[:])
	label := ctx.String()
	binary.BigEndian.PutUint64(buf[:], uint64(len(label)))
	mac.Write(buf[:])
	mac.Write([]byte(label))
	var out [sha256.Size]byte
	mac.Sum(out[:0])
	return out
}

// rosterSecret is the prologue, the epoch and the member's key. The key is
// in it so that two members with the same PSK derive different session
// keys; a failed resolution passes the roster's random stand-in key, which
// is a secret no client can have derived.
func rosterSecret(prologue []byte, epoch int64, key []byte) []byte {
	secret := make([]byte, 0, SaltSize+8+len(key))
	secret = append(secret, prologue...)
	secret = binary.BigEndian.AppendUint64(secret, uint64(epoch))
	return append(secret, key...)
}
