// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Password hashing uses PBKDF2-HMAC-SHA256 from the standard library, so Ares
// has no third-party crypto dependency. The iteration count follows current
// OWASP guidance for PBKDF2-SHA256. Hashes are self-describing, so the cost can
// be raised later and old hashes still verify.
const (
	pbkdf2Iter    = 600_000
	pbkdf2KeyLen  = 32
	pbkdf2SaltLen = 16
	pbkdf2Scheme  = "pbkdf2-sha256"

	// MinPasswordLen is the minimum accepted password length (super-admin and
	// user creation enforce it).
	MinPasswordLen = 12
)

// ErrWeakPassword is returned when a password is shorter than MinPasswordLen.
var ErrWeakPassword = fmt.Errorf("auth: password must be at least %d characters", MinPasswordLen)

// ErrBadHash is returned when a stored hash cannot be parsed.
var ErrBadHash = errors.New("auth: malformed password hash")

// HashPassword derives a self-describing PBKDF2 hash of password with a fresh
// random salt. It enforces the minimum length policy.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLen {
		return "", ErrWeakPassword
	}
	return derive(password)
}

// HashPasswordForDevSeed hashes password exactly like HashPassword but skips the
// minimum-length policy. It exists only so the local development seeder
// (cmd/ares-devseed) can provision a short, memorable demo credential. Nothing
// on a request path calls it: every account created through setup, the API or
// the UI still goes through HashPassword and its policy.
func HashPasswordForDevSeed(password string) (string, error) {
	if password == "" {
		return "", ErrWeakPassword
	}
	return derive(password)
}

// derive produces the self-describing PBKDF2 hash with a fresh random salt.
func derive(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	dk, err := kdf(password, salt, pbkdf2Iter, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("auth: derive: %w", err)
	}
	enc := base64.RawStdEncoding.EncodeToString
	return strings.Join([]string{pbkdf2Scheme, strconv.Itoa(pbkdf2Iter), enc(salt), enc(dk)}, "$"), nil
}

// VerifyPassword reports whether password matches the stored hash, in constant
// time. A malformed hash returns an error (never a silent false).
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != pbkdf2Scheme {
		return false, ErrBadHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, ErrBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, ErrBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrBadHash
	}
	got, err := kdf(password, salt, iter, len(want))
	if err != nil {
		return false, fmt.Errorf("auth: derive: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// kdfSlots caps how many password derivations run at once. One derivation is
// ~90 ms of CPU (600k PBKDF2-SHA256 rounds, deliberately), so a burst of
// sign-ins can occupy every core. ARES_KDF_CONCURRENCY=n lets sign-ins queue
// for n slots and keeps the other cores for requests. The default is one slot
// per usable CPU (no extra limit): on a 2-core load test, halving it doubled
// the time to sign 1,000 users in and did not improve request latency during
// a sign-in burst, so it is opt-in for larger hosts.
var kdfSlots = make(chan struct{}, kdfConcurrency(os.Getenv("ARES_KDF_CONCURRENCY"), runtime.GOMAXPROCS(0)))

func kdfConcurrency(env string, procs int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(env)); err == nil && n > 0 {
		return n
	}
	return max(procs, 1)
}

// kdf is pbkdf2.Key behind the concurrency cap.
func kdf(password string, salt []byte, iter, keyLen int) ([]byte, error) {
	kdfSlots <- struct{}{}
	defer func() { <-kdfSlots }()
	return pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
}
