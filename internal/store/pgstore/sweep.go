// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package pgstore

import (
	"context"
	"fmt"
	"time"

	sessionpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/session"
)

// DeleteExpired removes every session that expired before now. Sessions were
// only ever deleted when their token was presented again, so abandoned ones
// accumulated forever; the server sweeps periodically (indexed on expires_at).
func (r *SessionRepo) DeleteExpired(now time.Time) (int64, error) {
	n, err := sessionpkg.New().ExpiresAtLt(now).DeleteAll(context.Background(), r.ex)
	if err != nil {
		return 0, fmt.Errorf("pgstore: delete expired sessions: %w", err)
	}
	return n, nil
}
