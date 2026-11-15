// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"testing"
	"time"

	"github.com/gsoultan/ares-server/internal/auth"
)

func TestDeleteExpiredSessions(t *testing.T) {
	s := freshStore(t)
	r := s.Sessions()
	now := time.Now()
	_ = r.Save("old", auth.Session{UserID: "u", ExpiresAt: now.Add(-time.Hour)})
	_ = r.Save("live", auth.Session{UserID: "u", ExpiresAt: now.Add(time.Hour)})
	n, err := r.DeleteExpired(now)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v; want 1", n, err)
	}
	if _, ok, _ := r.Load("old"); ok {
		t.Error("expired session must be gone")
	}
	if _, ok, _ := r.Load("live"); !ok {
		t.Error("live session must stay")
	}
}
