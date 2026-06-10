// Package passwordhash provides Argon2id password hashing using the PHC string format.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024 // 64 MiB in KiB
	iterations  = 3
	parallelism = 1
	saltLength  = 16
	keyLength   = 32

	// Hard caps to prevent DoS via crafted hash strings
	maxMemory      = 512 * 1024 // 512 MiB in KiB
	maxIters       = 10
	maxParallelism = 4
)

// Hash generates an Argon2id hash of the given password and returns it as a
// PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	b64Salt := base64.RawURLEncoding.EncodeToString(salt)
	b64Hash := base64.RawURLEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism, b64Salt, b64Hash), nil
}

// Verify checks whether the given password matches the provided Argon2id PHC hash.
// It uses constant-time comparison to mitigate timing attacks.
func Verify(password, encodedHash string) (bool, error) {
	if encodedHash == "" {
		return false, fmt.Errorf("empty hash")
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != 19 {
		return false, fmt.Errorf("invalid or unsupported version")
	}

	var mem, iters, par int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return false, fmt.Errorf("invalid parameters: %w", err)
	}

	if mem > maxMemory || iters > maxIters || par > maxParallelism {
		return false, fmt.Errorf("argon2 parameters exceed safe limits")
	}

	salt, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid salt: %w", err)
	}

	hash, err := base64.RawURLEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid hash: %w", err)
	}

	computedHash := argon2.IDKey([]byte(password), salt, uint32(iters), uint32(mem), uint8(par), uint32(len(hash)))

	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return true, nil
	}
	return false, nil
}
