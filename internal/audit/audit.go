// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package audit provides a tamper-evident, hash-chained log. Every action,
// approval, scope denial and result is appended here. Each entry carries the
// hash of the previous one, so any later edit or deletion breaks the chain and
// Verify reports exactly where.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Entry is one immutable record in the chain.
type Entry struct {
	Seq      int       `json:"seq"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prevHash"`
	Hash     string    `json:"hash"`
}

func (e Entry) computeHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s\n%s",
		e.Seq,
		e.Time.UTC().Format(time.RFC3339Nano),
		e.Actor, e.Action, e.Target, e.Detail, e.PrevHash,
	)
	return hex.EncodeToString(h.Sum(nil))
}

// Log is an append-only chain of entries, safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	entries []Entry
	now     func() time.Time
}

// New returns an empty log using the real clock.
func New() *Log { return &Log{now: time.Now} }

// Load reconstructs a log from persisted entries. The entries already carry
// their hashes, so Verify checks the restored chain exactly as before; further
// Appends continue the chain from the last entry. The caller should Verify a
// freshly loaded log to detect tampering at rest.
func Load(entries []Entry) *Log {
	l := &Log{now: time.Now}
	l.entries = append(l.entries, entries...)
	return l
}

// newWithClock is used by tests to make timestamps deterministic.
func newWithClock(now func() time.Time) *Log { return &Log{now: now} }

// Append adds an entry linking to the current tip and returns it.
func (l *Log) Append(actor, action, target, detail string) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Hash
	}
	e := Entry{
		Seq:      len(l.entries),
		Time:     l.now(),
		Actor:    actor,
		Action:   action,
		Target:   target,
		Detail:   detail,
		PrevHash: prev,
	}
	e.Hash = e.computeHash()
	l.entries = append(l.entries, e)
	return e
}

// Entries returns a copy of the chain.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Verify walks the chain and confirms each entry's hash and its link to the
// previous one. It returns an error naming the first broken sequence number.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for i, e := range l.entries {
		if e.Seq != i {
			return fmt.Errorf("audit: entry %d has out-of-order seq %d", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: entry %d does not link to the previous entry", i)
		}
		if e.computeHash() != e.Hash {
			return fmt.Errorf("audit: entry %d has been altered", i)
		}
		prev = e.Hash
	}
	return nil
}
