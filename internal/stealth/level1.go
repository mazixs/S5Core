// Package stealth implements the detection checklist S5Core is measured
// against: the level-1 rules a censor applies to the first packet of a
// connection, and the level-2 checks for structure a protocol leaks about
// itself across many connections.
//
// It exists because the test it replaces measured Shannon entropy and passed
// at 5.0 bits per byte. Practically every encrypted or compressed stream
// clears that bar, so the test was green exactly when the product was most
// detectable - a high-entropy stream with no plausible prefix is what the
// rules below are written to find.
//
// The level-1 rules follow the fully-encrypted-traffic policy measured in
// "How the Great Firewall of China Detects and Blocks Fully Encrypted
// Traffic" (USENIX Security 2023). The policy is a blocklist with exemptions:
// a stream is blocked unless at least one exemption applies to it. Nothing
// here is a guarantee of undetectability - it is the absence of known
// signatures, which is a different and much weaker statement.
package stealth

import (
	"bytes"
	"math/bits"
)

// Exemption identifies which rule let a stream through. A censor applying
// this policy blocks everything that matches none of them, so for this
// product the goal is to match one - deliberately - rather than to look as
// random as possible.
type Exemption int

const (
	// ExNone means no exemption applied: this is the stream that gets blocked.
	ExNone Exemption = iota
	// Ex1PopcountOutsideRandomBand: the fraction of one bits is far enough
	// from one half that the packet cannot be an encrypted stream.
	//
	// The band is the trap. A perfectly random stream sits in the middle of
	// it, so maximising entropy drives a protocol towards being blocked, not
	// away from it.
	Ex1PopcountOutsideRandomBand
	// Ex2FirstSixPrintable: the first six bytes are printable ASCII, the way
	// a text protocol's command line begins.
	Ex2FirstSixPrintable
	// Ex3MostlyPrintable: more than half the packet is printable ASCII.
	Ex3MostlyPrintable
	// Ex4LongPrintableRun: more than twenty consecutive printable ASCII bytes.
	Ex4LongPrintableRun
	// Ex5KnownProtocolPrefix: the packet starts like a protocol the censor
	// has decided to allow - a TLS record, an HTTP request line.
	Ex5KnownProtocolPrefix
)

func (e Exemption) String() string {
	switch e {
	case ExNone:
		return "none (blocked)"
	case Ex1PopcountOutsideRandomBand:
		return "Ex1 popcount outside the random band"
	case Ex2FirstSixPrintable:
		return "Ex2 first six bytes printable"
	case Ex3MostlyPrintable:
		return "Ex3 more than half printable"
	case Ex4LongPrintableRun:
		return "Ex4 printable run over twenty bytes"
	case Ex5KnownProtocolPrefix:
		return "Ex5 known protocol prefix"
	}
	return "unknown"
}

// The band of one-bit density, in bits per byte, that the policy treats as
// "this could be encrypted". Outside it the stream is exempt.
//
// The paper writes the exemption with non-strict comparisons - popcount/len
// <= 3.4 or >= 4.6 - so the boundary itself is exempt, and inRandomBand
// spells it the same way. A packet landing exactly on 3.4 is a curiosity in
// floating point, but the checklist is a transcription of someone else's
// rule and reads better when it is one.
const (
	RandomBandLow  = 3.4
	RandomBandHigh = 4.6
)

// inRandomBand reports whether a packet's one-bit density leaves it inside
// the band, which is the case the policy does not exempt.
func inRandomBand(bpb float64) bool {
	return bpb > RandomBandLow && bpb < RandomBandHigh
}

// printableRunLimit is the length of a printable ASCII run that exempts a
// packet under Ex4.
const printableRunLimit = 20

// tlsRecordPrefix reports whether a packet opens with the TLS record header
// the policy exempts. The paper states the rule to the byte (section 4.3):
// the first three bytes must match [\x16-\x17]\x03[\x00-\x09].
//
// All three bytes matter, and this used to check two. Checking two is wrong
// in both directions: it misses \x17 openings the censor exempts, and - the
// direction that costs us - it exempts \x16\x03 followed by anything, so a
// prefix like 16 03 ff would pass this checklist and be blocked in the
// field. That matters for the countermeasure in docs/field/stealth.md, which
// is precisely a TLS record header in front of the first frame: the
// checklist has to agree with the rule it claims to implement, or measuring
// the countermeasure against it means nothing.
func tlsRecordPrefix(pkt []byte) bool {
	return len(pkt) >= 3 &&
		(pkt[0] == 0x16 || pkt[0] == 0x17) &&
		pkt[1] == 0x03 &&
		pkt[2] <= 0x09
}

// knownPrefixes are the protocol openings Ex5 recognises. A censor's list is
// longer and changes; this is the part of it that is documented and stable.
// TLS is not in this table: its rule constrains three bytes with a range in
// two of them, which a prefix match cannot express - see tlsRecordPrefix.
var knownPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
	[]byte("PATCH "),
	[]byte("SSH-"),
	[]byte("HTTP/"),
}

// Exempt returns the first exemption that applies to a stream's first packet,
// or ExNone when none does. ExNone is the answer that matters: it is the
// stream the policy blocks.
func Exempt(firstPacket []byte) Exemption {
	if len(firstPacket) == 0 {
		return ExNone
	}
	if !inRandomBand(BitsPerByte(firstPacket)) {
		return Ex1PopcountOutsideRandomBand
	}
	if len(firstPacket) >= 6 && allPrintable(firstPacket[:6]) {
		return Ex2FirstSixPrintable
	}
	if printableCount(firstPacket)*2 > len(firstPacket) {
		return Ex3MostlyPrintable
	}
	if longestPrintableRun(firstPacket) > printableRunLimit {
		return Ex4LongPrintableRun
	}
	if tlsRecordPrefix(firstPacket) {
		return Ex5KnownProtocolPrefix
	}
	for _, p := range knownPrefixes {
		if bytes.HasPrefix(firstPacket, p) {
			return Ex5KnownProtocolPrefix
		}
	}
	return ExNone
}

// BitsPerByte is the number of one bits per byte: 4.0 for a uniformly random
// stream, near 0 or 8 for structured data with a lot of zero or set bits.
func BitsPerByte(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ones := 0
	for _, c := range b {
		ones += bits.OnesCount8(c)
	}
	return float64(ones) / float64(len(b))
}

func printable(c byte) bool { return c >= 0x20 && c <= 0x7e }

func allPrintable(b []byte) bool {
	for _, c := range b {
		if !printable(c) {
			return false
		}
	}
	return true
}

func printableCount(b []byte) int {
	n := 0
	for _, c := range b {
		if printable(c) {
			n++
		}
	}
	return n
}

func longestPrintableRun(b []byte) int {
	best, run := 0, 0
	for _, c := range b {
		if printable(c) {
			run++
			if run > best {
				best = run
			}
			continue
		}
		run = 0
	}
	return best
}

// Level1 is the level-1 result for a corpus of first packets.
type Level1 struct {
	Streams int
	// Blocked is how many streams matched no exemption at all.
	Blocked int
	// ByExemption counts which rule saved the rest.
	ByExemption map[Exemption]int
	// MeanBitsPerByte is where the corpus sits relative to the Ex1 band.
	MeanBitsPerByte float64
}

// BlockedShare is the number the checklist exists to produce.
func (l Level1) BlockedShare() float64 {
	if l.Streams == 0 {
		return 0
	}
	return float64(l.Blocked) / float64(l.Streams)
}

// RunLevel1 applies the exemptions to every first packet in a corpus.
func RunLevel1(corpus [][]byte) Level1 {
	res := Level1{Streams: len(corpus), ByExemption: make(map[Exemption]int)}
	var sum float64
	for _, p := range corpus {
		sum += BitsPerByte(p)
		e := Exempt(p)
		res.ByExemption[e]++
		if e == ExNone {
			res.Blocked++
		}
	}
	if len(corpus) > 0 {
		res.MeanBitsPerByte = sum / float64(len(corpus))
	}
	return res
}
