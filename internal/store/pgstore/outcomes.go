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

	"github.com/gsoultan/storm/runtime"
	"github.com/jackc/pgx/v5/pgxpool"

	outcomepkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/joboutcome"
	"github.com/gsoultan/ares-server/internal/worker"
)

// Outcomes returns the persistent backend for job outcomes in this database.
func (s *Store) Outcomes() *OutcomeRepo { return &OutcomeRepo{ex: s.ex, pool: s.pool} }

// OutcomeRepo implements worker.OutcomeBackend over the job_outcomes table.
type OutcomeRepo struct {
	ex       runtime.Executor
	pool     *pgxpool.Pool
	sealer   worker.Sealer
	tenantOf func(engagementID string) string
}

var _ worker.OutcomeBackend = (*OutcomeRepo)(nil)

// SealWith encrypts outcomes stored from now on with sealer, per tenant;
// tenantOf maps an engagement id to its tenant id. Outcomes stored in plain
// form before stay readable. Call it before the repo is used, with a nil
// interface (not a nil pointer) to leave encryption off.
func (r *OutcomeRepo) SealWith(sealer worker.Sealer, tenantOf func(engagementID string) string) *OutcomeRepo {
	r.sealer, r.tenantOf = sealer, tenantOf
	return r
}

func (r *OutcomeRepo) tenant(engagementID string) string {
	if r.tenantOf == nil {
		return ""
	}
	return r.tenantOf(engagementID)
}

// PutOutcome implements worker.OutcomeBackend.
func (r *OutcomeRepo) PutOutcome(o worker.Outcome) error {
	data, err := worker.EncodeOutcome(o, r.sealer, r.tenant(o.Engagement))
	if err != nil {
		return err
	}
	n := outcomepkg.Create()
	n.SetJobID(o.JobID)
	n.SetEngagementID(o.Engagement)
	n.SetStartedAt(o.StartedAt)
	n.SetData(data)
	if _, err := n.OnConflictJobID().Insert(context.Background(), r.ex); err != nil {
		return fmt.Errorf("pgstore: save outcome %s: %w", o.JobID, err)
	}
	return nil
}

// OutcomesOf implements worker.OutcomeBackend.
func (r *OutcomeRepo) OutcomesOf(engagementID string) ([]worker.Outcome, error) {
	ctx := context.Background()
	var out []worker.Outcome
	for q := outcomepkg.New().EngagementIDEq(engagementID); ; {
		rows, err := q.All(ctx, r.ex, nil)
		if err != nil {
			return nil, fmt.Errorf("pgstore: load outcomes of %s: %w", engagementID, err)
		}
		for _, row := range rows {
			o, err := worker.DecodeOutcome(row.Data, r.sealer, r.tenant(engagementID), row.JobID)
			if err != nil {
				return nil, fmt.Errorf("pgstore: outcome %s: %w", row.JobID, err)
			}
			out = append(out, o)
		}
		if len(rows) < pageSize {
			return out, nil
		}
		q = outcomepkg.New().EngagementIDEq(engagementID).After(rows[len(rows)-1])
	}
}

// OutcomeIndex implements worker.OutcomeBackend. It reads the three key
// columns only, never the compressed results.
func (r *OutcomeRepo) OutcomeIndex(fn func(jobID, engagementID string, startedAt time.Time)) error {
	rows, err := r.pool.Query(context.Background(), `SELECT job_id, engagement_id, started_at FROM job_outcomes`)
	if err != nil {
		return fmt.Errorf("pgstore: load outcome index: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var job, eng string
		var started time.Time
		if err := rows.Scan(&job, &eng, &started); err != nil {
			return fmt.Errorf("pgstore: load outcome index: %w", err)
		}
		fn(job, eng, started)
	}
	return rows.Err()
}
