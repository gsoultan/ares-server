// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"container/list"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/eta"
)

// OutcomeBackend persists finished job outcomes. The datastores implement it;
// PersistentOutcomes puts the in-memory index, the live (running) outcomes and
// a bounded cache in front of it.
type OutcomeBackend interface {
	// PutOutcome stores a finished outcome (an upsert by job id).
	PutOutcome(o Outcome) error
	// OutcomesOf returns every stored outcome of an engagement.
	OutcomesOf(engagementID string) ([]Outcome, error)
	// OutcomeIndex calls fn for every stored outcome's job, without decoding
	// its results; it builds the job → engagement index at start.
	OutcomeIndex(fn func(jobID, engagementID string, startedAt time.Time)) error
}

// PersistentOutcomes is an OutcomeStore whose finished outcomes survive a
// restart and whose memory is bounded.
//
// Before, every outcome of every job ever run lived in memory and vanished on
// restart (with the findings derived from them). Now:
//
//   - a finished outcome is written to the backend once, compressed;
//   - running jobs' in-flight snapshots stay in memory only (they change on
//     every result and are rewritten when the job finishes);
//   - the outcomes of the most recently used engagements are kept decoded in an
//     LRU cache bounded by their total number of results, and an engagement
//     that fell out is read back from the backend on its next use;
//   - a small job → engagement index stays in memory so GetJob and ListJobs do
//     not need the backend.
//
// The read paths above (findings, risk, job views) are memoized on Version, so
// a cache miss costs one backend read per change, not one per request.
type PersistentOutcomes struct {
	backend OutcomeBackend

	mu       sync.Mutex
	jobs     map[string]jobRef     // every known job -> its engagement and start
	live     map[string]Outcome    // running jobs' latest snapshot
	versions map[string]uint64     // engagement -> bumps on every Save
	done     map[string]uint64     // engagement -> bumps when a job finishes
	cache    map[string]*cacheItem // engagement -> its finished outcomes, newest first
	lru      *list.List            // of engagement ids, most recent at the front
	cached   int                   // results held in the cache
	maxCache int                   // bound on cached results
	history  *eta.History          // recent run times per module, for time-left estimates
}

type jobRef struct {
	engagement string
	started    time.Time
}

type cacheItem struct {
	outcomes []Outcome // finished, newest StartedAt first
	results  int
	elem     *list.Element
}

// DefaultOutcomeCacheResults bounds how many results PersistentOutcomes keeps
// decoded in memory across all cached engagements.
const DefaultOutcomeCacheResults = 200_000

// NewPersistentOutcomes loads the job index from backend and returns the store.
// maxCachedResults <= 0 means DefaultOutcomeCacheResults.
func NewPersistentOutcomes(backend OutcomeBackend, maxCachedResults int) (*PersistentOutcomes, error) {
	if maxCachedResults <= 0 {
		maxCachedResults = DefaultOutcomeCacheResults
	}
	p := &PersistentOutcomes{
		backend:  backend,
		jobs:     make(map[string]jobRef),
		live:     make(map[string]Outcome),
		versions: make(map[string]uint64),
		done:     make(map[string]uint64),
		cache:    make(map[string]*cacheItem),
		lru:      list.New(),
		maxCache: maxCachedResults,
		history:  eta.NewHistory(),
	}
	err := backend.OutcomeIndex(func(jobID, eng string, started time.Time) {
		p.jobs[jobID] = jobRef{engagement: eng, started: started}
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Save implements OutcomeStore. A running outcome is held in memory; a
// finished one is persisted and leaves the live set.
func (p *PersistentOutcomes) Save(o Outcome) {
	if o.Running() {
		p.mu.Lock()
		p.live[o.JobID] = o
		p.jobs[o.JobID] = jobRef{engagement: o.Engagement, started: o.StartedAt}
		p.versions[o.Engagement]++
		p.mu.Unlock()
		return
	}
	// Persist outside the lock: one slow write must not stall every reader.
	err := p.backend.PutOutcome(o)

	p.mu.Lock()
	defer p.mu.Unlock()
	_, wasLive := p.live[o.JobID]
	if o.Error == "" && (wasLive || p.jobs[o.JobID] == (jobRef{})) {
		// First time this job is seen finished: learn its run time.
		p.history.Record(o.Module, len(o.Allowed), o.FinishedAt.Sub(o.StartedAt))
	}
	if err != nil {
		// Keep it served from memory rather than lose it; it is retried by
		// nothing, so say so loudly.
		log.Printf("outcomes: persist job %s: %v (kept in memory only)", o.JobID, err)
		p.live[o.JobID] = o
	} else {
		delete(p.live, o.JobID)
		if it, ok := p.cache[o.Engagement]; ok {
			p.insertCached(it, o)
		}
	}
	p.jobs[o.JobID] = jobRef{engagement: o.Engagement, started: o.StartedAt}
	p.versions[o.Engagement]++
	p.done[o.Engagement]++
}

// insertCached adds or replaces a finished outcome in a cached engagement.
func (p *PersistentOutcomes) insertCached(it *cacheItem, o Outcome) {
	for i, x := range it.outcomes {
		if x.JobID == o.JobID {
			p.cached -= len(x.Results)
			it.results -= len(x.Results)
			it.outcomes = append(it.outcomes[:i], it.outcomes[i+1:]...)
			break
		}
	}
	i := sort.Search(len(it.outcomes), func(i int) bool { return !it.outcomes[i].StartedAt.After(o.StartedAt) })
	it.outcomes = append(it.outcomes, Outcome{})
	copy(it.outcomes[i+1:], it.outcomes[i:])
	it.outcomes[i] = o
	it.results += len(o.Results)
	p.cached += len(o.Results)
	p.evict()
}

// Get implements OutcomeStore.
func (p *PersistentOutcomes) Get(jobID string) (Outcome, bool) {
	p.mu.Lock()
	if o, ok := p.live[jobID]; ok {
		p.mu.Unlock()
		return o, true
	}
	ref, ok := p.jobs[jobID]
	p.mu.Unlock()
	if !ok {
		return Outcome{}, false
	}
	for _, o := range p.finished(ref.engagement) {
		if o.JobID == jobID {
			return o, true
		}
	}
	return Outcome{}, false
}

// ByEngagement implements OutcomeStore: running and finished outcomes, newest
// first.
func (p *PersistentOutcomes) ByEngagement(engagementID string) []Outcome {
	done := p.finished(engagementID)
	p.mu.Lock()
	var running []Outcome
	for _, o := range p.live {
		if o.Engagement == engagementID {
			running = append(running, o)
		}
	}
	p.mu.Unlock()
	if len(running) == 0 {
		return append([]Outcome(nil), done...)
	}
	out := make([]Outcome, 0, len(done)+len(running))
	out = append(out, running...)
	for _, o := range done {
		dup := false
		for _, r := range running {
			if r.JobID == o.JobID {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, o)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// Estimate implements Estimator: how long a running job has left, from how
// long recent jobs of its module took.
func (p *PersistentOutcomes) Estimate(o Outcome, now time.Time) eta.Estimate {
	if !o.Running() {
		return eta.Estimate{State: eta.Done}
	}
	return p.history.Estimate(o.Module, len(o.Allowed), now.Sub(o.StartedAt), o.Progress)
}

// Version implements OutcomeStore.
func (p *PersistentOutcomes) Version(engagementID string) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.versions[engagementID]
}

// finished returns an engagement's persisted outcomes, newest first, from the
// cache or (on a miss) the backend. The returned slice is shared: read only.
func (p *PersistentOutcomes) finished(engagementID string) []Outcome {
	p.mu.Lock()
	if it, ok := p.cache[engagementID]; ok {
		p.lru.MoveToFront(it.elem)
		out := it.outcomes
		p.mu.Unlock()
		return out
	}
	gen := p.done[engagementID]
	p.mu.Unlock()

	loaded, err := p.backend.OutcomesOf(engagementID)
	if err != nil {
		log.Printf("outcomes: load engagement %s: %v", engagementID, err)
		return nil
	}
	sort.SliceStable(loaded, func(i, j int) bool { return loaded[i].StartedAt.After(loaded[j].StartedAt) })

	p.mu.Lock()
	defer p.mu.Unlock()
	if it, ok := p.cache[engagementID]; ok { // another reader filled it meanwhile
		p.lru.MoveToFront(it.elem)
		return it.outcomes
	}
	if p.done[engagementID] != gen {
		// A job finished while we read; what we read may predate it. Serve it
		// (the caller's next look sees the new Version) but do not cache it.
		return loaded
	}
	it := &cacheItem{outcomes: loaded}
	for _, o := range loaded {
		it.results += len(o.Results)
	}
	it.elem = p.lru.PushFront(engagementID)
	p.cache[engagementID] = it
	p.cached += it.results
	p.evict()
	return loaded
}

// evict drops least recently used engagements until the cache fits, always
// keeping the most recent one.
func (p *PersistentOutcomes) evict() {
	for p.cached > p.maxCache && p.lru.Len() > 1 {
		back := p.lru.Back()
		id := back.Value.(string)
		it := p.cache[id]
		p.cached -= it.results
		delete(p.cache, id)
		p.lru.Remove(back)
	}
}
