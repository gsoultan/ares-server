// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"fmt"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/q"
)

// DeleteExpired removes every session that expired before now. Sessions were
// only ever deleted when their token was presented again, so abandoned ones
// accumulated forever; the server sweeps periodically.
func (r *SessionRepo) DeleteExpired(now time.Time) (int64, error) {
	var recs []sessionRecord
	if err := r.db.Select(q.Lt("ExpiresAt", now)).Find(&recs); err != nil && err != storm.ErrNotFound {
		return 0, fmt.Errorf("stormstore: find expired sessions: %w", err)
	}
	var n int64
	for i := range recs {
		if err := r.db.DeleteStruct(&recs[i]); err != nil && err != storm.ErrNotFound {
			return n, fmt.Errorf("stormstore: delete expired session: %w", err)
		}
		n++
	}
	return n, nil
}
