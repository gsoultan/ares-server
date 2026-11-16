// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package model declares the storm models for the Ares PostgreSQL datastore.
// storm generates one typed query package per table from these structs; the
// pgstore repositories are written against that generated code.
//
// The engagement's authorization, scope snapshot and tamper-evident audit trail
// live in a single jsonb document, not timestamptz columns: JSON preserves full
// nanosecond timestamps, so the audit hash-chain still verifies when the trail
// is reloaded. Everything else is a plain column, so emails get a real unique
// constraint and tenant ids a real index.
package model

import (
	"time"

	"github.com/gsoultan/storm"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/settings"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/scope"
)

// All returns every model, for storm.Build and storm generate.
func All() []any {
	return []any{&Tenant{}, &Engagement{}, &AuditEntry{}, &JobOutcome{}, &User{}, &Session{}, &Setting{}, &SetupConfig{}}
}

// Tenant is a client workspace.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

func (t *Tenant) Schema(tb *storm.Table) { tb.PrimaryKey(&t.ID) }

// EngagementDoc is the jsonb payload of an engagement: the parts whose shape is
// nested and whose timestamps must survive at nanosecond precision.
type EngagementDoc struct {
	Status        string                    `json:"status"`
	Authorization *engagement.Authorization `json:"authorization,omitempty"`
	Scope         scope.Snapshot            `json:"scope"`
	// Audit is only read, from engagements written before the trail moved to
	// its own append-only table (AuditEntry); Open migrates it out and new
	// headers never carry it.
	Audit     []audit.Entry               `json:"audit,omitempty"`
	Detection map[string]detection.Record `json:"detection,omitempty"`
}

// Engagement is one assessment. Data is a jsonb document (see EngagementDoc).
type Engagement struct {
	ID        string
	TenantID  string
	Name      string
	CreatedAt time.Time
	Data      EngagementDoc
}

func (e *Engagement) Schema(tb *storm.Table) {
	tb.PrimaryKey(&e.ID)
	tb.Index(&e.TenantID)
}

// AuditEntry is one entry of an engagement's hash-chained audit trail, stored
// as its own append-only row so saving an engagement writes only the entries
// added since the last save instead of rewriting the whole trail. Rows are
// never updated or deleted; the chain is verified on load as before.
type AuditEntry struct {
	EngagementID string
	Seq          int64
	Entry        audit.Entry
}

func (a *AuditEntry) Schema(tb *storm.Table) { tb.PrimaryKey(&a.EngagementID, &a.Seq) }

// JobOutcome is one finished job's outcome (its gate decision and results),
// stored compressed (worker.EncodeOutcome). They used to live only in memory
// and were lost on restart, with the findings derived from them.
type JobOutcome struct {
	JobID        string
	EngagementID string
	StartedAt    time.Time
	Data         []byte
}

func (j *JobOutcome) Schema(tb *storm.Table) {
	tb.PrimaryKey(&j.JobID)
	tb.Index(&j.EngagementID)
}

// User is an account. Email carries a unique constraint so the database enforces
// one account per email; the password is stored only as its PBKDF2 hash.
type User struct {
	ID           string
	TenantID     string
	Email        string
	Name         string
	Role         string
	PasswordHash string
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) Schema(tb *storm.Table) {
	tb.PrimaryKey(&u.ID)
	tb.Col(&u.Email).Size(320)
	tb.Unique(&u.Email)
	tb.Index(&u.TenantID)
}

// Session is a bearer session keyed by the token's hash. The raw token is never
// stored.
type Session struct {
	TokenHash string
	UserID    string
	TenantID  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Sessions are looked up by token hash; user_id serves revoking every session
// of an account, expires_at the periodic sweep of expired sessions.
func (s *Session) Schema(tb *storm.Table) {
	tb.PrimaryKey(&s.TokenHash)
	tb.Index(&s.UserID)
	tb.Index(&s.ExpiresAt)
}

// Setting is one workspace's settings. Secrets are stored already sealed
// (ciphertext) in the jsonb payload, so the database never holds a plaintext
// credential.
type Setting struct {
	TenantID string
	AI       settings.AIConfig
	Secrets  map[string]settings.SealedSecret
}

func (s *Setting) Schema(tb *storm.Table) { tb.PrimaryKey(&s.TenantID) }

// SetupConfig is the single first-run configuration and initialization marker.
type SetupConfig struct {
	ID            string
	Initialized   bool
	InitializedAt time.Time
	DBDriver      string
	DBPath        string
}

func (s *SetupConfig) Schema(tb *storm.Table) { tb.PrimaryKey(&s.ID) }
