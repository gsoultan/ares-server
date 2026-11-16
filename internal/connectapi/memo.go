// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"hash/maphash"
	"sync"
)

// memo caches read-path results that are pure functions of versioned inputs
// (an engagement's outcomes, its finding statuses, its audit length). Each
// entry carries the fingerprint of the inputs it was built from; a lookup with
// a different fingerprint rebuilds it. Nothing is ever served stale, so no TTL
// is needed: an entry is only reused while its inputs are provably unchanged.
//
// Cached values are shared between concurrent requests and must be treated as
// read-only by every caller (clone before mutating).
type memo struct {
	mu  sync.Mutex
	m   map[string]memoEntry
	max int
}

type memoEntry struct {
	fp uint64
	v  any
}

func newMemo(max int) *memo { return &memo{m: make(map[string]memoEntry), max: max} }

// get returns the cached value for key if it was built from inputs with
// fingerprint fp, else builds, stores and returns a fresh one. build runs
// outside the lock, so a slow build never blocks other keys.
func (c *memo) get(key string, fp uint64, build func() any) any {
	c.mu.Lock()
	if e, ok := c.m[key]; ok && e.fp == fp {
		c.mu.Unlock()
		return e.v
	}
	c.mu.Unlock()

	v := build()

	c.mu.Lock()
	if len(c.m) >= c.max {
		// Bounded memory: drop everything rather than track recency. Entries are
		// cheap to rebuild and the hot ones come straight back.
		clear(c.m)
	}
	c.m[key] = memoEntry{fp: fp, v: v}
	c.mu.Unlock()
	return v
}

// fingerprint hashes the version inputs of one cache entry.
type fingerprint struct{ h maphash.Hash }

var memoSeed = maphash.MakeSeed()

func newFingerprint() *fingerprint {
	f := &fingerprint{}
	f.h.SetSeed(memoSeed)
	return f
}

func (f *fingerprint) str(s string) *fingerprint {
	f.h.WriteString(s)
	f.h.WriteByte(0)
	return f
}

func (f *fingerprint) num(n uint64) *fingerprint {
	var b [8]byte
	for i := range b {
		b[i] = byte(n >> (8 * i))
	}
	f.h.Write(b[:])
	return f
}

func (f *fingerprint) sum() uint64 { return f.h.Sum64() }
