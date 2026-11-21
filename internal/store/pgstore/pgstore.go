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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gsoultan/storm"
	"github.com/gsoultan/storm/migrate"
	"github.com/gsoultan/storm/runtime"
	"github.com/gsoultan/storm/runtime/pgxdrv"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gsoultan/ares-server/internal/audit"
	"github.com/gsoultan/ares-server/internal/engagement"
	auditpkg "github.com/gsoultan/ares-server/internal/store/pgstore/gen/auditentry"
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
	db      pgxdrv.Pool
	mu      sync.Mutex
	m       map[string]*engagement.Engagement
	tenants map[string]*tenant.Tenant
	saved   map[string]*savedState // what is already in Postgres, per engagement
}

// savedState is what Save last wrote for one engagement: how many audit
// entries are persisted and a hash of the header document. Save then writes
// only the entries after that point, and the header only when it changed. Its
// mutex serializes Saves of the same engagement (the worker and an API call can
// race), so two Saves never write the same entries.
type savedState struct {
	mu         sync.Mutex
	auditN     int
	headerHash [32]byte
}

// pageSize is the generated queries' default LIMIT; reads that must see every
// row page with a keyset cursor until a short page.
const pageSize = 1000

// auditCopyThreshold is the number of new audit entries above which Save bulk
// loads them with COPY inside a transaction instead of one pipelined batch.
const auditCopyThreshold = 64

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
		db:      pgxdrv.Pool{P: pool},
		m:       make(map[string]*engagement.Engagement),
		tenants: make(map[string]*tenant.Tenant),
		saved:   make(map[string]*savedState),
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
	// Every read pages: the generated queries LIMIT 1000 by default, and a
	// plain All would silently drop every row after the first page.
	for q := tenantpkg.New(); ; {
		trows, err := q.All(ctx, s.ex, nil)
		if err != nil {
			return fmt.Errorf("pgstore: load tenants: %w", err)
		}
		for _, r := range trows {
			s.tenants[r.ID] = &tenant.Tenant{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt}
		}
		if len(trows) < pageSize {
			break
		}
		q = tenantpkg.New().After(trows[len(trows)-1])
	}

	trails, err := s.loadAudit(ctx)
	if err != nil {
		return err
	}

	for q := engagementpkg.New(); ; {
		erows, err := q.All(ctx, s.ex, nil)
		if err != nil {
			return fmt.Errorf("pgstore: load engagements: %w", err)
		}
		for _, r := range erows {
			if err := s.loadEngagement(ctx, r, trails[r.ID]); err != nil {
				return err
			}
		}
		if len(erows) < pageSize {
			break
		}
		q = engagementpkg.New().After(erows[len(erows)-1])
	}
	return nil
}

// loadAudit reads every audit entry, grouped by engagement in seq order.
func (s *Store) loadAudit(ctx context.Context) (map[string][]audit.Entry, error) {
	trails := map[string][]audit.Entry{}
	for q := auditpkg.New(); ; {
		rows, err := q.All(ctx, s.ex, nil)
		if err != nil {
			return nil, fmt.Errorf("pgstore: load audit trail: %w", err)
		}
		for _, r := range rows {
			var e audit.Entry
			if err := r.Entry.Unmarshal(&e); err != nil {
				return nil, fmt.Errorf("pgstore: decode audit entry %s/%d: %w", r.EngagementID, r.Seq, err)
			}
			trails[r.EngagementID] = append(trails[r.EngagementID], e)
		}
		if len(rows) < pageSize {
			break
		}
		q = auditpkg.New().After(rows[len(rows)-1])
	}
	for id, t := range trails {
		sort.Slice(t, func(i, j int) bool { return t[i].Seq < t[j].Seq })
		trails[id] = t
	}
	return trails, nil
}

// loadEngagement restores one engagement from its header row and audit rows.
// An engagement written before the trail had its own table still carries it in
// the header; it is moved out here, once, in one transaction.
func (s *Store) loadEngagement(ctx context.Context, r engagementpkg.Row, trail []audit.Entry) error {
	var doc engmodel.EngagementDoc
	if err := r.Data.Unmarshal(&doc); err != nil {
		return fmt.Errorf("pgstore: decode engagement %s: %w", r.ID, err)
	}
	legacy := len(doc.Audit) > 0
	if legacy && len(trail) == 0 {
		trail = doc.Audit
	}
	sc, err := scope.Restore(doc.Scope)
	if err != nil {
		return fmt.Errorf("pgstore: restore scope for %s: %w", r.ID, err)
	}
	log := audit.Load(trail)
	if err := log.Verify(); err != nil {
		return fmt.Errorf("pgstore: audit trail for %s failed verification at rest: %w", r.ID, err)
	}
	tenantID := r.TenantID
	if tenantID == "" {
		tenantID = tenant.DefaultID
	}
	eng := engagement.Restore(r.ID, tenantID, r.Name, engagement.Status(doc.Status), doc.Authorization, r.CreatedAt, sc, log, doc.Detection)
	eng.Consent = doc.Consent
	s.m[r.ID] = eng

	st := &savedState{auditN: len(trail)}
	s.saved[r.ID] = st
	if legacy {
		// Write the trail as rows and the header without it, atomically. The
		// saved state starts at zero entries and an unknown header, so this is
		// just a Save.
		st.auditN = 0
		if err := s.Save(eng); err != nil {
			return fmt.Errorf("pgstore: migrate audit trail of %s: %w", r.ID, err)
		}
		return nil
	}
	if raw, err := headerJSON(eng); err == nil {
		st.headerHash = sha256.Sum256(raw)
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
//
// The audit trail is append-only, so Save writes only the entries added since
// the last Save, as their own rows, and rewrites the small header document
// (status, authorization, scope, detection) only when it changed. Both go in
// one pipelined batch, which Postgres runs as one implicit transaction; a large
// backlog of entries is bulk loaded with COPY inside an explicit transaction.
// The cost of a Save is therefore proportional to what changed, not to the
// length of the trail, and no dead copies of the trail pile up in the table.
func (s *Store) Save(e *engagement.Engagement) error {
	s.mu.Lock()
	s.m[e.ID] = e
	st, ok := s.saved[e.ID]
	if !ok {
		st = &savedState{}
		s.saved[e.ID] = st
	}
	s.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	raw, err := headerJSON(e)
	if err != nil {
		return fmt.Errorf("pgstore: encode %s: %w", e.ID, err)
	}
	hash := sha256.Sum256(raw)
	headerChanged := hash != st.headerHash

	fresh, total := e.Audit.Since(st.auditN)
	if total < st.auditN {
		// The trail never shrinks; a shorter one is a different log object.
		return fmt.Errorf("pgstore: save %s: audit trail shrank from %d to %d entries", e.ID, st.auditN, total)
	}
	if !headerChanged && len(fresh) == 0 {
		return nil
	}

	ctx := context.Background()
	var header *engagementpkg.Ins
	if headerChanged {
		n := engagementpkg.Create()
		n.SetID(e.ID)
		n.SetTenantID(e.TenantID)
		n.SetName(e.Name)
		n.SetCreatedAt(e.CreatedAt)
		n.SetData(runtime.JSON(raw))
		header = n.OnConflictID()
	}
	if len(fresh) > auditCopyThreshold {
		err = s.saveBulk(ctx, e.ID, header, fresh)
	} else {
		err = s.saveBatch(ctx, e.ID, header, fresh)
	}
	if err != nil {
		return fmt.Errorf("pgstore: save %s: %w", e.ID, err)
	}
	st.auditN = total
	st.headerHash = hash
	return nil
}

// saveBatch writes the header (when given) and a few audit rows in one round trip.
func (s *Store) saveBatch(ctx context.Context, id string, header *engagementpkg.Ins, fresh []audit.Entry) error {
	ops := make([]runtime.BatchOp, 0, len(fresh)+1)
	if header != nil {
		op, err := header.Op()
		if err != nil {
			return err
		}
		ops = append(ops, op)
	}
	for _, en := range fresh {
		row, err := auditRow(id, en)
		if err != nil {
			return err
		}
		ops = append(ops, auditpkg.InsertOp(row))
	}
	return s.ex.Batch(ctx, ops, nil)
}

// saveBulk writes the header (when given) and many audit rows in one transaction,
// loading the rows with COPY.
func (s *Store) saveBulk(ctx context.Context, id string, header *engagementpkg.Ins, fresh []audit.Entry) error {
	rows := make([]auditpkg.Row, 0, len(fresh))
	for _, en := range fresh {
		row, err := auditRow(id, en)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}
	tx, err := s.db.StartTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if header != nil {
		if _, err := header.Insert(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := auditpkg.InsertAll(ctx, tx, rows); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func auditRow(id string, en audit.Entry) (auditpkg.Row, error) {
	raw, err := marshalJSON(en)
	if err != nil {
		return auditpkg.Row{}, err
	}
	return auditpkg.Row{EngagementID: id, Seq: int64(en.Seq), Entry: raw}, nil
}

// headerJSON encodes everything about an engagement except its audit trail.
func headerJSON(e *engagement.Engagement) ([]byte, error) {
	return json.Marshal(engmodel.EngagementDoc{
		Status:        string(e.Status),
		Authorization: e.Authorization,
		Scope:         e.Scope.Snapshot(),
		Detection:     e.Detection,
		Consent:       e.ConsentForStore(),
	})
}

// Close releases the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}
