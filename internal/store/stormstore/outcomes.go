// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package stormstore

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/gsoultan/ares-server/internal/worker"
)

// outcomeBucket holds finished job outcomes, one key per job: engagement id, a
// zero byte, the job's start time (big-endian Unix nanoseconds), then the job
// id. An engagement's outcomes are one contiguous key range, oldest first, and
// the job index is rebuilt from the keys alone. Values are worker.EncodeOutcome
// (zstd-compressed JSON, sealed per tenant when encryption is on).
var outcomeBucket = []byte("outcomes")

func outcomeKey(o worker.Outcome) []byte {
	k := make([]byte, 0, len(o.Engagement)+1+8+len(o.JobID))
	k = append(k, o.Engagement...)
	k = append(k, 0)
	k = binary.BigEndian.AppendUint64(k, uint64(o.StartedAt.UnixNano()))
	return append(k, o.JobID...)
}

func parseOutcomeKey(k []byte) (eng string, started time.Time, job string, ok bool) {
	i := bytes.IndexByte(k, 0)
	if i < 0 || len(k) < i+1+8 {
		return "", time.Time{}, "", false
	}
	ns := binary.BigEndian.Uint64(k[i+1 : i+9])
	return string(k[:i]), time.Unix(0, int64(ns)), string(k[i+9:]), true
}

// Outcomes returns the persistent backend for job outcomes in this database.
func (s *Store) Outcomes() *OutcomeRepo { return &OutcomeRepo{db: s.db.Bolt} }

// OutcomeRepo implements worker.OutcomeBackend over bbolt.
type OutcomeRepo struct {
	db       *bolt.DB
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
	v, err := worker.EncodeOutcome(o, r.sealer, r.tenant(o.Engagement))
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(outcomeBucket)
		if err != nil {
			return err
		}
		return b.Put(outcomeKey(o), v)
	})
}

// OutcomesOf implements worker.OutcomeBackend.
func (r *OutcomeRepo) OutcomesOf(engagementID string) ([]worker.Outcome, error) {
	var out []worker.Outcome
	prefix := append([]byte(engagementID), 0)
	err := r.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(outcomeBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			_, _, job, _ := parseOutcomeKey(k)
			o, err := worker.DecodeOutcome(v, r.sealer, r.tenant(engagementID), job)
			if err != nil {
				return fmt.Errorf("stormstore: outcome %q: %w", k, err)
			}
			out = append(out, o)
		}
		return nil
	})
	return out, err
}

// OutcomeIndex implements worker.OutcomeBackend.
func (r *OutcomeRepo) OutcomeIndex(fn func(jobID, engagementID string, startedAt time.Time)) error {
	return r.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(outcomeBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if eng, started, job, ok := parseOutcomeKey(k); ok {
				fn(job, eng, started)
			}
		}
		return nil
	})
}
