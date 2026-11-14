// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package uuid

import (
	"regexp"
	"testing"
	"time"
)

var v7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewV7Shape(t *testing.T) {
	id := NewV7()
	if !v7Pattern.MatchString(id) {
		t.Fatalf("id %q is not a canonical UUIDv7", id)
	}
}

func TestNewV7Unique(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		id := NewV7()
		if seen[id] {
			t.Fatalf("duplicate id generated: %s", id)
		}
		seen[id] = true
	}
}

// TestNewV7SortsByTime confirms ids created later never sort before earlier
// ones across a millisecond boundary — the point of v7 over v4.
func TestNewV7SortsByTime(t *testing.T) {
	first := NewV7()
	time.Sleep(2 * time.Millisecond)
	second := NewV7()
	if !(first < second) {
		t.Fatalf("expected %q < %q (v7 is time-ordered)", first, second)
	}
}
