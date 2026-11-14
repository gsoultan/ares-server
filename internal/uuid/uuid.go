// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package uuid generates UUID version 7 identifiers. A v7 id begins with a
// 48-bit Unix-millisecond timestamp and fills the rest with random bits, so ids
// are globally unique, practically unguessable (unlike a sequential counter,
// which leaks how many exist and invites enumeration), and sort in creation
// order. Generation uses only the standard library, keeping Ares dependency-free.
package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewV7 returns a new UUID version 7 in canonical 8-4-4-4-12 form.
func NewV7() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	// 48-bit big-endian millisecond timestamp.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	// Remaining bytes are random. crypto/rand never fails on supported platforms.
	_, _ = rand.Read(b[6:])
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return format(b)
}

func format(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
