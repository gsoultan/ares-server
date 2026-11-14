// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package engagement models a single authorized testing engagement: who it is
// for, what is in scope, whether permission has been granted, and its own
// tamper-evident audit log. Nothing runs against an engagement's targets until
// it is authorized.
package engagement

import (
	"errors"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/tenant"
	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares/detection"
	"github.com/gsoultan/ares/scope"
)

// ErrUnknownTenant is returned when an engagement is created under a workspace
// that does not exist. Creating work in a ghost tenant would silently escape
// isolation, so the store refuses it rather than inventing the tenant.
var ErrUnknownTenant = errors.New("tenant not found")

// Status is where an engagement sits in its lifecycle.
type Status string

const (
	// StatusDraft means scope may still be edited and nothing can run.
	StatusDraft Status = "draft"
	// StatusAuthorized means a signed permission is on file and jobs may run.
	StatusAuthorized Status = "authorized"
	// StatusHalted means an operator pressed the kill switch; nothing runs.
	StatusHalted Status = "halted"
)

// Authorization records the signed permission to test.
type Authorization struct {
	Document   string    `json:"document"`   // name or reference of the signed file
	ApprovedBy string    `json:"approvedBy"` // the person who approved it
	ApprovedAt time.Time `json:"approvedAt"`
}

// Engagement is one authorized test. The Scope is the permission gate; Audit is
// its immutable record. TenantID is the workspace that owns it: a store never
// returns an engagement to a caller acting in a different workspace.
type Engagement struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenantId"`
	Name          string         `json:"name"`
	Status        Status         `json:"status"`
	Scope         *scope.Scope   `json:"-"`
	Authorization *Authorization `json:"authorization,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	Audit         *audit.Log     `json:"-"`
	// Detection holds the operator's recorded defender response per ATT&CK
	// technique the engagement's tests exercised (the blue/purple seam).
	Detection map[string]detection.Record `json:"-"`
}

// SetDetection records the defender's response for one technique and writes it
// to the audit trail. It is how the blue/purple seam is scored.
func (e *Engagement) SetDetection(technique string, o detection.Outcome, note, actor string) error {
	if technique == "" {
		return errors.New("detection needs a technique")
	}
	if !detection.Valid(o) {
		return errors.New("unknown detection outcome")
	}
	if e.Detection == nil {
		e.Detection = map[string]detection.Record{}
	}
	e.Detection[technique] = detection.Record{
		Technique: technique,
		Outcome:   o,
		Note:      note,
		UpdatedAt: time.Now(),
	}
	e.Audit.Append(actor, "detection-recorded", technique, string(o))
	return nil
}

// Detections returns the recorded defender responses, keyed by technique.
func (e *Engagement) Detections() map[string]detection.Record {
	return e.Detection
}

// CanRun reports whether jobs may run: authorized and not halted.
func (e *Engagement) CanRun() (bool, string) {
	switch e.Status {
	case StatusAuthorized:
		return true, ""
	case StatusHalted:
		return false, "the engagement is halted"
	default:
		return false, "the engagement is not authorized yet"
	}
}

// Authorize attaches a signed permission and moves the engagement to
// authorized. It records the approval in the audit log.
func (e *Engagement) Authorize(a Authorization) error {
	if a.Document == "" || a.ApprovedBy == "" {
		return errors.New("authorization needs a document and an approver")
	}
	if a.ApprovedAt.IsZero() {
		a.ApprovedAt = time.Now()
	}
	e.Authorization = &a
	e.Status = StatusAuthorized
	e.Audit.Append(a.ApprovedBy, "authorization-approved", e.ID, a.Document)
	return nil
}

// Halt is the kill switch: it stops the engagement from running anything more.
func (e *Engagement) Halt(actor string) {
	e.Status = StatusHalted
	e.Audit.Append(actor, "engagement-halted", e.ID, "")
}

// Store keeps engagements, grouped into client workspaces (tenants). The
// in-memory implementation is used for tests and ephemeral runs; a Storm
// (bbolt) implementation persists the same shape behind this interface.
//
// Isolation is the store's contract: Create binds an engagement to a tenant,
// List returns only one tenant's engagements, and Get is an unscoped lookup by
// id used by internal callers (the worker) — the API boundary checks the
// returned engagement's TenantID against the caller's workspace before handing
// it back. Every store always holds the default workspace, so an empty tenant
// id resolves to it and a single-client deployment needs no setup.
//
// Handlers and the worker mutate an engagement in place (scope edits,
// authorization, the kill switch, audit appends) and then call Save so a
// persistent store can flush the change. For the in-memory store Save is a
// no-op on state that is already live.
type Store interface {
	CreateTenant(name string) *tenant.Tenant
	GetTenant(id string) (*tenant.Tenant, bool)
	ListTenants() []*tenant.Tenant
	// SetTenantName renames an existing workspace (used by first-run setup to name
	// the default workspace). It returns ErrUnknownTenant if the id is unknown.
	SetTenantName(id, name string) error

	Create(tenantID, name string) (*Engagement, error)
	Get(id string) (*Engagement, bool)
	List(tenantID string) []*Engagement
	Save(e *Engagement) error
}

// ResolveTenant maps an empty tenant id to the default workspace, so callers
// that omit a workspace operate on the default one consistently.
func ResolveTenant(id string) string {
	if id == "" {
		return tenant.DefaultID
	}
	return id
}

// Restore rebuilds an engagement from persisted parts. It is used by a
// persistent Store when loading from disk; the scope and audit log are
// reconstructed by their own packages so their invariants still hold.
func Restore(id, tenantID, name string, status Status, auth *Authorization, createdAt time.Time, sc *scope.Scope, log *audit.Log, detections map[string]detection.Record) *Engagement {
	return &Engagement{
		ID:            id,
		TenantID:      tenantID,
		Name:          name,
		Status:        status,
		Scope:         sc,
		Authorization: auth,
		CreatedAt:     createdAt,
		Audit:         log,
		Detection:     detections,
	}
}

// MemStore is an in-memory Store, safe for concurrent use.
type MemStore struct {
	mu      sync.Mutex
	m       map[string]*Engagement
	tenants map[string]*tenant.Tenant
}

// NewMemStore returns an in-memory store holding only the default workspace.
func NewMemStore() *MemStore {
	s := &MemStore{
		m:       make(map[string]*Engagement),
		tenants: make(map[string]*tenant.Tenant),
	}
	s.tenants[tenant.DefaultID] = &tenant.Tenant{
		ID:        tenant.DefaultID,
		Name:      tenant.DefaultName,
		CreatedAt: time.Now(),
	}
	return s
}

// CreateTenant adds a new client workspace.
func (s *MemStore) CreateTenant(name string) *tenant.Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &tenant.Tenant{ID: uuid.NewV7(), Name: name, CreatedAt: time.Now()}
	s.tenants[t.ID] = t
	return t
}

// SetTenantName renames a workspace.
func (s *MemStore) SetTenantName(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[ResolveTenant(id)]
	if !ok {
		return ErrUnknownTenant
	}
	t.Name = name
	return nil
}

// GetTenant returns a workspace by id.
func (s *MemStore) GetTenant(id string) (*tenant.Tenant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[ResolveTenant(id)]
	return t, ok
}

// ListTenants returns every workspace.
func (s *MemStore) ListTenants() []*tenant.Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*tenant.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	return out
}

// Create makes a new draft engagement in a workspace, with an empty scope and a
// fresh audit log. An empty tenant id means the default workspace; an unknown
// tenant is refused.
func (s *MemStore) Create(tenantID, name string) (*Engagement, error) {
	tenantID = ResolveTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrUnknownTenant
	}
	id := uuid.NewV7()
	e := &Engagement{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		Status:    StatusDraft,
		Scope:     scope.New(),
		CreatedAt: time.Now(),
		Audit:     audit.New(),
	}
	e.Audit.Append("system", "engagement-created", id, name)
	s.m[id] = e
	return e, nil
}

// Save is a no-op for the in-memory store: the engagement it holds is the same
// pointer callers mutate, so there is nothing to flush. It keeps the Store
// interface uniform with persistent implementations.
func (s *MemStore) Save(e *Engagement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[e.ID] = e
	return nil
}

// Get returns an engagement by id, across all workspaces. It is an internal
// lookup (the worker runs a queued job by id); the API boundary checks the
// returned engagement's TenantID before exposing it to a caller.
func (s *MemStore) Get(id string) (*Engagement, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	return e, ok
}

// List returns the engagements in one workspace. An empty tenant id means the
// default workspace.
func (s *MemStore) List(tenantID string) []*Engagement {
	tenantID = ResolveTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Engagement, 0, len(s.m))
	for _, e := range s.m {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out
}
