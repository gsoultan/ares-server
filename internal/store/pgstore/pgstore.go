// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package pgstore is a persistent engagement.Store (plus the auth, settings and
// setup stores) backed by PostgreSQL through github.com/gsoultan/storm. It is
// the production datastore: the same interfaces stormstore satisfies, so the
// server is wired to one or the other at start with no change above the store.
//
// storm is model-first — the table shapes live in the model package and the
// typed query/insert/update code in gen/, generated with `storm generate`. This
// file holds the store lifecycle and the engagement repository on top of that
// generated surface.
//
// Like stormstore it keeps the live engagements in memory — callers mutate the
// same pointers the in-memory store hands out — and writes each change through
// to Postgres. The engagement record (status, authorization, scope snapshot and
// the tamper-evident audit trail) is stored as a single jsonb document, not as
// timestamptz columns: JSON preserves the full nanosecond timestamps, so the
// audit hash-chain still verifies when the trail is reloaded.
package pgstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gsoultan/storm"
	"github.com/gsoultan/storm/migrate"
	"github.com/gsoultan/storm/runtime"
	"github.com/gsoultan/storm/runtime/pgxdrv"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/engagement"
	engagementpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/engagement"
	tenantpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/tenant"
	engmodel "github.com/gsoultan/ares-server/internal/store/pgstore/model"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares/scope"
)

// Store is a persistent engagement.Store over PostgreSQL via storm.
type Store struct {
	pool    *pgxpool.Pool
	ex      runtime.Executor
	mu      sync.Mutex
	m       map[string]*engagement.Engagement
	tenants map[string]*tenant.Tenant
}

var _ engagement.Store = (*Store)(nil)

// Open connects to the Postgres database named by dsn, applies the storm schema
// (automigrate), and loads every stored workspace and engagement into memory. It
// verifies each audit chain as it loads and refuses to open if one has been
// tampered with at rest, naming the engagement.
func Open(dsn string) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstore: ping: %w", err)
	}

	// Automigrate the schema the models declare. AutoPool takes an advisory lock,
	// computes the plan under it, and applies it in one transaction.
	sch, err := storm.Build(engmodel.All()...)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstore: build schema: %w", err)
	}
	if _, err := migrate.AutoPool(ctx, pool, sch, migrate.AutoOptions{}); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstore: migrate: %w", err)
	}

	s := &Store{
		pool:    pool,
		ex:      pgxdrv.Pool{P: pool},
		m:       make(map[string]*engagement.Engagement),
		tenants: make(map[string]*tenant.Tenant),
	}
	if err := s.load(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	// Every store always holds the default workspace, so empty tenant ids resolve
	// to it and engagements persisted before tenancy stay reachable.
	if _, ok := s.tenants[tenant.DefaultID]; !ok {
		def := &tenant.Tenant{ID: tenant.DefaultID, Name: tenant.DefaultName, CreatedAt: time.Now()}
		s.tenants[def.ID] = def
		if err := s.saveTenant(ctx, def); err != nil {
			pool.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) load(ctx context.Context) error {
	trows, err := tenantpkg.New().All(ctx, s.ex, nil)
	if err != nil {
		return fmt.Errorf("pgstore: load tenants: %w", err)
	}
	for _, r := range trows {
		s.tenants[r.ID] = &tenant.Tenant{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt}
	}

	erows, err := engagementpkg.New().All(ctx, s.ex, nil)
	if err != nil {
		return fmt.Errorf("pgstore: load engagements: %w", err)
	}
	for _, r := range erows {
		var doc engmodel.EngagementDoc
		if err := r.Data.Unmarshal(&doc); err != nil {
			return fmt.Errorf("pgstore: decode engagement %s: %w", r.ID, err)
		}
		sc, err := scope.Restore(doc.Scope)
		if err != nil {
			return fmt.Errorf("pgstore: restore scope for %s: %w", r.ID, err)
		}
		log := audit.Load(doc.Audit)
		if err := log.Verify(); err != nil {
			return fmt.Errorf("pgstore: audit trail for %s failed verification at rest: %w", r.ID, err)
		}
		tenantID := r.TenantID
		if tenantID == "" {
			tenantID = tenant.DefaultID
		}
		eng := engagement.Restore(r.ID, tenantID, r.Name, engagement.Status(doc.Status), doc.Authorization, r.CreatedAt, sc, log, doc.Detection)
		s.m[r.ID] = eng
	}
	return nil
}

// CreateTenant adds and persists a new client workspace.
func (s *Store) CreateTenant(name string) *tenant.Tenant {
	t := &tenant.Tenant{ID: uuid.NewV7(), Name: name, CreatedAt: time.Now()}
	s.mu.Lock()
	s.tenants[t.ID] = t
	s.mu.Unlock()
	_ = s.saveTenant(context.Background(), t)
	return t
}

// GetTenant returns a workspace by id.
func (s *Store) GetTenant(id string) (*tenant.Tenant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[engagement.ResolveTenant(id)]
	return t, ok
}

// ListTenants returns every workspace.
func (s *Store) ListTenants() []*tenant.Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*tenant.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	return out
}

// SetTenantName renames a workspace and persists the change.
func (s *Store) SetTenantName(id, name string) error {
	s.mu.Lock()
	t, ok := s.tenants[engagement.ResolveTenant(id)]
	if !ok {
		s.mu.Unlock()
		return engagement.ErrUnknownTenant
	}
	t.Name = name
	s.mu.Unlock()
	return s.saveTenant(context.Background(), t)
}

// saveTenant upserts a workspace by primary key.
func (s *Store) saveTenant(ctx context.Context, t *tenant.Tenant) error {
	n := tenantpkg.Create()
	n.SetID(t.ID)
	n.SetName(t.Name)
	n.SetCreatedAt(t.CreatedAt)
	if _, err := n.OnConflictID().Insert(ctx, s.ex); err != nil {
		return fmt.Errorf("pgstore: save tenant %s: %w", t.ID, err)
	}
	return nil
}

// Create makes a new draft engagement in a workspace, persists it, and caches
// the live pointer. An empty tenant id means the default workspace; an unknown
// tenant is refused.
func (s *Store) Create(tenantID, name string) (*engagement.Engagement, error) {
	tenantID = engagement.ResolveTenant(tenantID)
	s.mu.Lock()
	if _, ok := s.tenants[tenantID]; !ok {
		s.mu.Unlock()
		return nil, engagement.ErrUnknownTenant
	}
	s.mu.Unlock()
	id := uuid.NewV7()

	eng := engagement.Restore(id, tenantID, name, engagement.StatusDraft, nil, time.Now(), scope.New(), audit.New(), nil)
	eng.Audit.Append("system", "engagement-created", id, name)

	s.mu.Lock()
	s.m[id] = eng
	s.mu.Unlock()

	if err := s.Save(eng); err != nil {
		return nil, err
	}
	return eng, nil
}

// Get returns the live engagement by id, across all workspaces. The API boundary
// checks the returned engagement's TenantID before exposing it.
func (s *Store) Get(id string) (*engagement.Engagement, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	return e, ok
}

// List returns the live engagements in one workspace. An empty tenant id means
// the default workspace.
func (s *Store) List(tenantID string) []*engagement.Engagement {
	tenantID = engagement.ResolveTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*engagement.Engagement, 0, len(s.m))
	for _, e := range s.m {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out
}

// Save flushes the current state of an engagement to Postgres. Callers invoke it
// after mutating an engagement (scope edits, authorization, the kill switch,
// audit appends).
func (s *Store) Save(e *engagement.Engagement) error {
	s.mu.Lock()
	s.m[e.ID] = e
	s.mu.Unlock()

	doc := engmodel.EngagementDoc{
		Status:        string(e.Status),
		Authorization: e.Authorization,
		Scope:         e.Scope.Snapshot(),
		Audit:         e.Audit.Entries(),
		Detection:     e.Detection,
	}
	raw, err := marshalJSON(doc)
	if err != nil {
		return fmt.Errorf("pgstore: encode %s: %w", e.ID, err)
	}
	n := engagementpkg.Create()
	n.SetID(e.ID)
	n.SetTenantID(e.TenantID)
	n.SetName(e.Name)
	n.SetCreatedAt(e.CreatedAt)
	n.SetData(raw)
	if _, err := n.OnConflictID().Insert(context.Background(), s.ex); err != nil {
		return fmt.Errorf("pgstore: save %s: %w", e.ID, err)
	}
	return nil
}

// Close releases the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}
