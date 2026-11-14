// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package audit

import (
	"testing"
	"time"
)

func TestChainVerifies(t *testing.T) {
	l := New()
	l.Append("white-cell", "engagement-created", "eng-1", "")
	l.Append("engagement-lead", "authorization-approved", "eng-1", "authorization-letter.pdf")
	l.Append("worker", "scope-denied", "10.0.9.15", "on the exclusion list")
	if err := l.Verify(); err != nil {
		t.Fatalf("a freshly built chain must verify: %v", err)
	}
	if got := len(l.Entries()); got != 3 {
		t.Fatalf("want 3 entries, got %d", got)
	}
}

func TestTamperIsDetected(t *testing.T) {
	l := New()
	l.Append("a", "one", "t1", "")
	l.Append("b", "two", "t2", "")
	l.Append("c", "three", "t3", "")

	// Tamper with a middle entry directly in the slice.
	l.entries[1].Detail = "changed after the fact"
	if err := l.Verify(); err == nil {
		t.Fatal("Verify must detect an altered entry")
	}
}

func TestDeletionIsDetected(t *testing.T) {
	l := New()
	l.Append("a", "one", "t1", "")
	l.Append("b", "two", "t2", "")
	l.Append("c", "three", "t3", "")

	// Remove the middle entry; the chain link should break.
	l.entries = append(l.entries[:1], l.entries[2:]...)
	if err := l.Verify(); err == nil {
		t.Fatal("Verify must detect a deleted entry")
	}
}

func TestDeterministicHashWithFixedClock(t *testing.T) {
	fixed := time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)
	l := newWithClock(func() time.Time { return fixed })
	e := l.Append("actor", "action", "target", "detail")
	if e.Hash == "" {
		t.Fatal("hash must not be empty")
	}
	// Recomputing the same fields yields the same hash.
	if e.computeHash() != e.Hash {
		t.Fatal("hash must be reproducible from the entry's fields")
	}
}
