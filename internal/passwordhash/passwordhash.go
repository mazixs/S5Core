// Package passwordhash provides Argon2id password hashing using the PHC string format.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024 // 64 MiB in KiB
	iterations  = 3
	parallelism = 1
	saltLength  = 16
	keyLength   = 32

	// MemoryBytes is what one run of the parameters above asks the allocator
	// for. It is exported because the cost of this function is the reason
	// callers have to bound how many of them run at once - see
	// internal/userstore/kdfgate.go.
	MemoryBytes = memory * 1024

	// Hard caps to prevent DoS via crafted hash strings
	maxMemory      = 512 * 1024 // 512 MiB in KiB
	maxIters       = 10
	maxParallelism = 4

	// Lower bounds, audit finding F15. Argon2 answers some of these with a
	// panic rather than an error - t=0 is "number of rounds too small", p=0
	// is "parallelism degree too low", an empty tag is a nil dereference -
	// and the string that carries them comes from a file an operator edits by
	// hand. A parameter out of range has to be an error here, because one
	// line of a users file must not be able to stop the process.
	minMemory      = 8 // KiB; argon2 raises anything below 8*p to it anyway
	minIters       = 1
	minParallelism = 1

	// Sizes this package will check a password against. RFC 9106 asks for at
	// least 8 bytes of salt and at least 4 of tag; 16 is the shortest tag
	// worth calling a password hash. The upper bounds exist so that a crafted
	// string cannot ask for work nobody writes: what Hash produces is 16 and
	// 32.
	minSaltLength = 8
	maxSaltLength = 64
	minKeyLength  = 16
	maxKeyLength  = 64
)

// params are the three Argon2id cost parameters, in the order a PHC string
// spells them.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

// parseParams reads "m=<n>,t=<n>,p=<n>" and nothing else.
//
// fmt.Sscanf used to do this, and it was wrong twice over: it stops at the
// last verb, so "m=65536,t=3,p=1,everything after this" parsed clean, and it
// reads into int, so "t=-1" became 4294967295 rounds on the conversion to
// uint32 and "m=-1" asked the allocator for 4 TiB - on the machine this was
// tried, one such line in the account file killed the process with "runtime:
// out of memory" before any panic was reached. Reading each field as an
// unsigned number rules out the sign at the parser rather than at the bound,
// and comparing the whole field rules out the tail.
func parseParams(field string) (params, error) {
	var p params
	names := [...]string{"m=", "t=", "p="}
	parts := strings.Split(field, ",")
	if len(parts) != len(names) {
		return p, fmt.Errorf("invalid parameters: want m=,t=,p=, got %q", field)
	}

	var values [len(names)]uint64
	for i, part := range parts {
		if !strings.HasPrefix(part, names[i]) {
			return p, fmt.Errorf("invalid parameters: want %q at position %d of %q", names[i], i+1, field)
		}
		digits := part[len(names[i]):]
		// ParseUint refuses a sign, an empty string and underscores at base
		// 10, which is exactly the set of spellings that used to get through.
		v, err := strconv.ParseUint(digits, 10, 32)
		if err != nil {
			return p, fmt.Errorf("invalid parameter %s%s: %w", names[i], digits, err)
		}
		values[i] = v
	}

	if values[0] < minMemory || values[0] > maxMemory {
		return p, fmt.Errorf("argon2 memory %d outside [%d, %d]", values[0], minMemory, maxMemory)
	}
	if values[1] < minIters || values[1] > maxIters {
		return p, fmt.Errorf("argon2 iterations %d outside [%d, %d]", values[1], minIters, maxIters)
	}
	if values[2] < minParallelism || values[2] > maxParallelism {
		return p, fmt.Errorf("argon2 parallelism %d outside [%d, %d]", values[2], minParallelism, maxParallelism)
	}

	return params{
		memory:      uint32(values[0]),
		iterations:  uint32(values[1]),
		parallelism: uint8(values[2]),
	}, nil
}

// parse takes a PHC string apart and refuses everything Argon2id would not
// survive. It is the whole of the format check: Verify runs the KDF on what
// it returns and nothing else, and Validate is this function without the KDF.
func parse(encodedHash string) (p params, salt, hash []byte, err error) {
	if encodedHash == "" {
		return p, nil, nil, fmt.Errorf("empty hash")
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return p, nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}
	if parts[0] != "" {
		return p, nil, nil, fmt.Errorf("invalid hash format: expected a leading $")
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}
	// Compared whole rather than scanned: "v=19 and then some" is not
	// version 19.
	if parts[2] != "v=19" {
		return p, nil, nil, fmt.Errorf("invalid or unsupported version: %s", parts[2])
	}

	p, err = parseParams(parts[3])
	if err != nil {
		return p, nil, nil, err
	}

	salt, err = decodeField(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("invalid salt: %w", err)
	}
	if len(salt) < minSaltLength || len(salt) > maxSaltLength {
		return p, nil, nil, fmt.Errorf("salt length %d outside [%d, %d]", len(salt), minSaltLength, maxSaltLength)
	}

	hash, err = decodeField(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("invalid hash: %w", err)
	}
	if len(hash) < minKeyLength || len(hash) > maxKeyLength {
		return p, nil, nil, fmt.Errorf("hash length %d outside [%d, %d]", len(hash), minKeyLength, maxKeyLength)
	}

	return p, salt, hash, nil
}

// Validate reports whether a stored string is one a password can be checked
// against. It is the same reading Verify does, without running the KDF, so
// that a hash an operator mistyped is caught when the account file is read
// rather than when someone tries to log in.
func Validate(encodedHash string) error {
	_, _, _, err := parse(encodedHash)
	return err
}

// Audit finding P3-1. The PHC string format spells its salt and hash in
// base64 with the standard alphabet and no padding; this package used the
// URL-safe alphabet, which differs in two characters ("-_" against "+/").
// Nothing broke, because both ends of the check were ours - and that is the
// whole problem: a hash S5Core writes has to be readable by any other Argon2id
// implementation, or the account file is ours forever.
//
// phcEncoding is what Hash writes. legacyEncoding is only ever read, for the
// hashes earlier builds wrote; Standardise converts one into the other without
// the password, because the alphabet is a spelling of the same bytes.
var (
	phcEncoding    = base64.RawStdEncoding
	legacyEncoding = base64.RawURLEncoding
)

// decodeField reads one base64 field of a PHC string in either alphabet. The
// standard one is tried first, so the cost of the fallback is paid only by
// hashes that still carry the old spelling.
func decodeField(field string) ([]byte, error) {
	if b, err := phcEncoding.DecodeString(field); err == nil {
		return b, nil
	}
	return legacyEncoding.DecodeString(field)
}

// Standardise rewrites a hash written in the URL-safe alphabet into the PHC
// standard one. It returns the hash to store and whether anything changed.
//
// No password is involved: the salt and the hash are the same bytes either
// way, so an account file can be brought up to the standard by reading it, and
// the account keeps working with the password it already has. A string this
// package cannot parse is returned untouched - Verify will report why.
func Standardise(encodedHash string) (string, bool) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return encodedHash, false
	}
	changed := false
	for _, i := range [...]int{4, 5} {
		if _, err := phcEncoding.DecodeString(parts[i]); err == nil {
			continue
		}
		raw, err := legacyEncoding.DecodeString(parts[i])
		if err != nil {
			return encodedHash, false
		}
		parts[i] = phcEncoding.EncodeToString(raw)
		changed = true
	}
	if !changed {
		return encodedHash, false
	}
	return strings.Join(parts, "$"), true
}

// Hash generates an Argon2id hash of the given password and returns it as a
// PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	b64Salt := phcEncoding.EncodeToString(salt)
	b64Hash := phcEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism, b64Salt, b64Hash), nil
}

// Verify checks whether the given password matches the provided Argon2id PHC hash.
// It uses constant-time comparison to mitigate timing attacks.
func Verify(password, encodedHash string) (bool, error) {
	p, salt, hash, err := parse(encodedHash)
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, uint32(len(hash)))

	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return true, nil
	}
	return false, nil
}
