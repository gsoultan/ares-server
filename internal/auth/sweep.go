// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package auth

import (
	"context"
	"log"
	"time"
)

// ExpiredSweeper is implemented by session stores that can delete expired
// sessions in bulk.
type ExpiredSweeper interface {
	DeleteExpired(now time.Time) (int64, error)
}

// DeleteExpired implements ExpiredSweeper.
func (s *MemSessionStore) DeleteExpired(now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for h, sess := range s.m {
		if now.After(sess.ExpiresAt) {
			delete(s.m, h)
			n++
		}
	}
	return n, nil
}

// SweepExpiredSessions deletes expired sessions every interval until ctx ends.
// Expired sessions are already refused at authentication; this only reclaims
// the storage of the ones nobody presents again.
func SweepExpiredSessions(ctx context.Context, s ExpiredSweeper, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n, err := s.DeleteExpired(now); err != nil {
				log.Printf("session sweep: %v", err)
			} else if n > 0 {
				log.Printf("session sweep: removed %d expired sessions", n)
			}
		}
	}
}
