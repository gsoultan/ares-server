// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package secret

import (
	"bytes"
	"strings"
	"testing"
)

func newSealer(t *testing.T) *Sealer {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newSealer(t)
	secrets := []string{"", "sk-ant-api03-deadbeef", "a longer api key with spaces and \x00 bytes"}
	for _, want := range secrets {
		sealed, err := s.SealString(want)
		if err != nil {
			t.Fatalf("Seal(%q): %v", want, err)
		}
		if !IsSealed(sealed) {
			t.Errorf("sealed value lacks prefix: %q", sealed)
		}
		if strings.Contains(sealed, want) && want != "" {
			t.Errorf("plaintext leaked into sealed value: %q", sealed)
		}
		got, err := s.OpenString(sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != want {
			t.Errorf("round trip = %q, want %q", got, want)
		}
	}
}

func TestSealIsRandomized(t *testing.T) {
	s := newSealer(t)
	a, _ := s.SealString("same-secret")
	b, _ := s.SealString("same-secret")
	if a == b {
		t.Error("sealing the same plaintext twice must differ (random nonce)")
	}
}

func TestWrongKeyCannotOpen(t *testing.T) {
	s1 := newSealer(t)
	s2 := newSealer(t)
	sealed, _ := s1.SealString("top-secret")
	if _, err := s2.Open(sealed); err != ErrDecrypt {
		t.Errorf("open with wrong key err = %v, want ErrDecrypt", err)
	}
}

func TestTamperDetected(t *testing.T) {
	s := newSealer(t)
	sealed, _ := s.SealString("integrity-matters")
	// Flip a byte in the base64 body.
	body := []byte(sealed)
	body[len(body)-2] ^= 0x01
	if _, err := s.Open(string(body)); err == nil {
		t.Error("tampered ciphertext must not open")
	}
}

func TestMalformedRejected(t *testing.T) {
	s := newSealer(t)
	for _, bad := range []string{"", "plaintext", "ares.secret.v1:not-base64!!", sealPrefix + "AAAA"} {
		if _, err := s.Open(bad); err == nil {
			t.Errorf("Open(%q) must fail", bad)
		}
	}
}

func TestKeySizeEnforced(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err != ErrKeySize {
		t.Errorf("NewSealer(16 bytes) err = %v, want ErrKeySize", err)
	}
}

func TestEncodeDecodeKey(t *testing.T) {
	key, _ := NewKey()
	got, err := DecodeKey(EncodeKey(key))
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("key did not survive encode/decode")
	}
	if _, err := DecodeKey("c2hvcnQ="); err != ErrKeySize { // "short"
		t.Errorf("DecodeKey(short) err = %v, want ErrKeySize", err)
	}
	if _, err := DecodeKey("!!!not base64"); err != ErrFormat {
		t.Errorf("DecodeKey(garbage) err = %v, want ErrFormat", err)
	}
}
