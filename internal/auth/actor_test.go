// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestActorPrefersTheSignedInAccount(t *testing.T) {
	signedIn := WithSession(context.Background(), Session{UserID: "u1", Email: "ana@example.com"})
	noEmail := WithSession(context.Background(), Session{UserID: "u2"})
	anon := context.Background()

	cases := []struct {
		name          string
		ctx           context.Context
		claimed, want string
	}{
		{"session wins over a claimed name", signedIn, "someone-else", "ana@example.com"},
		{"session with no claim", signedIn, "", "ana@example.com"},
		{"session without email falls back to the user id", noEmail, "someone-else", "user:u2"},
		{"no session uses the claim", anon, "lead", "lead"},
		{"no session and no claim uses the fallback", anon, "", "operator"},
	}
	for _, c := range cases {
		if got := Actor(c.ctx, c.claimed, "operator"); got != c.want {
			t.Errorf("%s: Actor = %q, want %q", c.name, got, c.want)
		}
	}
}

// The email is derived from the account on each request; it must never be
// persisted with the session or sent to the client as part of it.
func TestSessionEmailIsNotSerialized(t *testing.T) {
	b, err := json.Marshal(Session{UserID: "u1", Email: "ana@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ana@example.com") {
		t.Fatalf("session JSON carries the email: %s", b)
	}
}
