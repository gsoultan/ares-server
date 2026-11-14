// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package stormstore is a persistent engagement.Store backed by Storm over
// bbolt, a single-file embedded key/value database. It keeps the live
// engagements in memory (so callers mutate the same pointers, exactly as the
// in-memory store behaves) and writes each change through to disk, so the
// control plane survives a restart with its workspaces, scope, authorization
// and tamper-evident audit trail intact.
//
// bbolt is a single-writer store: writes serialize, which is fine for a control
// plane but is why heavy write fan-out belongs in the worker's own results path,
// not here.
package stormstore

import (
	"fmt"
	"sync"
	"time"

	"github.com/asdine/storm/v3"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/scope"
)

// record is the on-disk shape of an engagement. The scope and audit log are
// stored through their serializable snapshots, not their live objects, so
// their invariants are rebuilt on load rather than smuggled across the boundary.
type record struct {
	ID            string `storm:"id"`
	TenantID      string `storm:"index"`
	Name          string
	Status        string
	Authorization *engagement.Authorization
	CreatedAt     time.Time
	Scope         scope.Snapshot
	Audit         []audit.Entry
	Detection     map[string]detection.Record
}

// tenantRecord is the on-disk shape of a client workspace. Storm keeps each
// struct type in its own bucket, so tenants and engagements persist side by side.
type tenantRecord struct {
	ID        string `storm:"id"`
	Name      string
	CreatedAt time.Time
}

// Store is a persistent engagement.Store.
type Store struct {
	db      *storm.DB
	mu      sync.Mutex
	m       map[string]*engagement.Engagement
	tenants map[string]*tenant.Tenant
}

// compile-time check that Store satisfies the interface.
var _ engagement.Store = (*Store)(nil)

// Open opens (creating if needed) the database at path and loads every stored
// workspace and engagement into memory. It verifies each audit chain as it
// loads and refuses to open if one has been tampered with at rest, naming the
// engagement.
func Open(path string) (*Store, error) {
	db, err := storm.Open(path)
	if err != nil {
		return nil, fmt.Errorf("stormstore: open %q: %w", path, err)
	}
	s := &Store{
		db:      db,
		m:       make(map[string]*engagement.Engagement),
		tenants: make(map[string]*tenant.Tenant),
	}
	if err := s.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Every store always holds the default workspace, so empty tenant ids
	// resolve to it and engagements persisted before tenancy stay reachable.
	if _, ok := s.tenants[tenant.DefaultID]; !ok {
		def := &tenant.Tenant{ID: tenant.DefaultID, Name: tenant.DefaultName, CreatedAt: time.Now()}
		s.tenants[def.ID] = def
		if err := s.saveTenant(def); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) load() error {
	var tenants []tenantRecord
	if err := s.db.All(&tenants); err != nil && err != storm.ErrNotFound {
		return fmt.Errorf("stormstore: load tenants: %w", err)
	}
	for _, t := range tenants {
		s.tenants[t.ID] = &tenant.Tenant{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt}
	}

	var recs []record
	if err := s.db.All(&recs); err != nil && err != storm.ErrNotFound {
		return fmt.Errorf("stormstore: load: %w", err)
	}
	for _, r := range recs {
		sc, err := scope.Restore(r.Scope)
		if err != nil {
			return fmt.Errorf("stormstore: restore scope for %s: %w", r.ID, err)
		}
		log := audit.Load(r.Audit)
		if err := log.Verify(); err != nil {
			return fmt.Errorf("stormstore: audit trail for %s failed verification at rest: %w", r.ID, err)
		}
		// Engagements written before tenancy existed carry no workspace; they
		// belong to the default one.
		tenantID := r.TenantID
		if tenantID == "" {
			tenantID = tenant.DefaultID
		}
		eng := engagement.Restore(r.ID, tenantID, r.Name, engagement.Status(r.Status), r.Authorization, r.CreatedAt, sc, log, r.Detection)
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

	_ = s.saveTenant(t)
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
	return s.saveTenant(t)
}

func (s *Store) saveTenant(t *tenant.Tenant) error {
	rec := tenantRecord{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt}
	if err := s.db.Save(&rec); err != nil {
		return fmt.Errorf("stormstore: save tenant %s: %w", t.ID, err)
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

// Get returns the live engagement by id, across all workspaces. The API
// boundary checks the returned engagement's TenantID before exposing it.
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

// Save flushes the current state of an engagement to disk. Callers invoke it
// after mutating an engagement (scope edits, authorization, the kill switch,
// audit appends).
func (s *Store) Save(e *engagement.Engagement) error {
	s.mu.Lock()
	s.m[e.ID] = e
	s.mu.Unlock()

	rec := record{
		ID:            e.ID,
		TenantID:      e.TenantID,
		Name:          e.Name,
		Status:        string(e.Status),
		Authorization: e.Authorization,
		CreatedAt:     e.CreatedAt,
		Scope:         e.Scope.Snapshot(),
		Audit:         e.Audit.Entries(),
		Detection:     e.Detection,
	}
	if err := s.db.Save(&rec); err != nil {
		return fmt.Errorf("stormstore: save %s: %w", e.ID, err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }
