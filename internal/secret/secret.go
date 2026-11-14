// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package secret provides authenticated encryption at rest for the values Ares
// must store but must never expose: AI and OSINT provider API keys, database
// credentials, and the like. A single master key (32 bytes, AES-256) seals and
// opens values with AES-256-GCM, so every stored secret is confidential and
// tamper-evident. The plaintext of a sealed value never leaves this package
// except through Open, and Open is called only to use a secret, never to return
// one over the API.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// KeySize is the master-key length in bytes (AES-256).
const KeySize = 32

// sealPrefix tags a sealed blob with its format version, so the on-disk format
// can evolve without ambiguity. Everything after the prefix is base64(nonce ||
// ciphertext+tag).
const sealPrefix = "ares.secret.v1:"

var (
	// ErrKeySize is returned when a master key is not exactly KeySize bytes.
	ErrKeySize = fmt.Errorf("secret: master key must be %d bytes", KeySize)
	// ErrFormat is returned when a sealed value is not in the expected format.
	ErrFormat = errors.New("secret: malformed sealed value")
	// ErrDecrypt is returned when a sealed value fails authentication or
	// decryption (wrong key, or tampered ciphertext). It deliberately carries no
	// detail that could aid an attacker.
	ErrDecrypt = errors.New("secret: cannot open sealed value")
)

// Sealer seals and opens secrets with a fixed master key. It is safe for
// concurrent use: the underlying AEAD is stateless and a fresh random nonce is
// drawn per Seal.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte master key. The key is used only to
// construct the cipher and is not retained in any other form.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext and returns a versioned, base64-encoded sealed value
// safe to persist. A random nonce is generated for every call, so sealing the
// same plaintext twice yields different blobs.
func (s *Sealer) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secret: nonce: %w", err)
	}
	ct := s.aead.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, 0, len(nonce)+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return sealPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// SealString is a convenience wrapper over Seal for string secrets.
func (s *Sealer) SealString(plaintext string) (string, error) {
	return s.Seal([]byte(plaintext))
}

// Open authenticates and decrypts a value produced by Seal. A wrong key or any
// tampering yields ErrDecrypt with no further detail.
func (s *Sealer) Open(sealed string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, sealPrefix)
	if !ok {
		return nil, ErrFormat
	}
	blob, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, ErrFormat
	}
	ns := s.aead.NonceSize()
	if len(blob) < ns {
		return nil, ErrFormat
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// OpenString is a convenience wrapper over Open for string secrets.
func (s *Sealer) OpenString(sealed string) (string, error) {
	pt, err := s.Open(sealed)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// IsSealed reports whether v carries the sealed-value prefix. It does not verify
// that v can be opened; it only distinguishes a sealed blob from plaintext, so
// callers never seal an already-sealed value or hand plaintext to Open.
func IsSealed(v string) bool {
	return strings.HasPrefix(v, sealPrefix)
}

// NewKey generates a cryptographically random 32-byte master key.
func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("secret: generate key: %w", err)
	}
	return key, nil
}

// EncodeKey renders a master key as base64 for display or storage (shown once at
// setup so the operator can save it; persisted to the key file for boot).
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey parses a base64-encoded master key and validates its length.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrFormat
	}
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	return key, nil
}
