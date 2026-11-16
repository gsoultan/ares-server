// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/ares/module"

	"github.com/gsoultan/ares-server/internal/eta"
)

// memBackend is an in-memory OutcomeBackend that counts reads.
type memBackend struct {
	mu    sync.Mutex
	m     map[string]Outcome
	reads int
}

func newMemBackend() *memBackend { return &memBackend{m: map[string]Outcome{}} }

func (b *memBackend) PutOutcome(o Outcome) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Store the encoded form, as a real backend does.
	enc, err := EncodeOutcome(o, nil, "")
	if err != nil {
		return err
	}
	dec, err := DecodeOutcome(enc, nil, "", o.JobID)
	if err != nil {
		return err
	}
	b.m[o.JobID] = dec
	return nil
}

func (b *memBackend) OutcomesOf(eng string) ([]Outcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads++
	var out []Outcome
	for _, o := range b.m {
		if o.Engagement == eng {
			out = append(out, o)
		}
	}
	return out, nil
}

func (b *memBackend) OutcomeIndex(fn func(string, string, time.Time)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, o := range b.m {
		fn(o.JobID, o.Engagement, o.StartedAt)
	}
	return nil
}

func outcome(job, eng string, start time.Time, results int, done bool) Outcome {
	o := Outcome{JobID: job, Engagement: eng, Module: "webcheck", StartedAt: start}
	for i := 0; i < results; i++ {
		o.Results = append(o.Results, module.Result{Capability: "webcheck", Kind: "finding",
			Target: module.Target{URL: fmt.Sprintf("https://app.example/%d", i)},
			Data:   map[string]any{"title": "t", "n": float64(i)}})
	}
	if done {
		o.FinishedAt = start.Add(time.Second)
	}
	return o
}

func TestPersistentOutcomesSurviveRestart(t *testing.T) {
	be := newMemBackend()
	p, err := NewPersistentOutcomes(be, 0)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	p.Save(outcome("j1", "e1", t0, 2, false)) // running: memory only
	if len(be.m) != 0 {
		t.Fatal("a running outcome must not be persisted")
	}
	if o, ok := p.Get("j1"); !ok || !o.Running() {
		t.Fatal("running outcome must be readable")
	}
	p.Save(outcome("j1", "e1", t0, 3, true))
	p.Save(outcome("j2", "e1", t0.Add(time.Minute), 1, true))
	if got := p.ByEngagement("e1"); len(got) != 2 || got[0].JobID != "j2" || len(got[1].Results) != 3 {
		t.Fatalf("ByEngagement = %+v, want j2 then j1 (3 results)", got)
	}

	// A new process over the same backend sees everything finished.
	p2, err := NewPersistentOutcomes(be, 0)
	if err != nil {
		t.Fatal(err)
	}
	if o, ok := p2.Get("j1"); !ok || len(o.Results) != 3 || o.Running() {
		t.Fatalf("after restart: j1 ok=%v results=%d", ok, len(o.Results))
	}
	if got := p2.ByEngagement("e1"); len(got) != 2 {
		t.Fatalf("after restart: %d outcomes, want 2", len(got))
	}
}

func TestPersistentOutcomesCacheIsBoundedAndReused(t *testing.T) {
	be := newMemBackend()
	p, _ := NewPersistentOutcomes(be, 10) // at most 10 cached results
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		p.Save(outcome(fmt.Sprintf("j%d", i), fmt.Sprintf("e%d", i), t0, 6, true))
	}
	_ = p.ByEngagement("e0")
	_ = p.ByEngagement("e0")
	if be.reads != 1 {
		t.Fatalf("a cached engagement must not be re-read: %d reads", be.reads)
	}
	_ = p.ByEngagement("e1") // 12 results > 10: e0 is evicted
	if p.cached > 10 && p.lru.Len() > 1 {
		t.Fatalf("cache over bound: %d results in %d engagements", p.cached, p.lru.Len())
	}
	_ = p.ByEngagement("e0")
	if be.reads != 3 {
		t.Fatalf("an evicted engagement must be read again: %d reads, want 3", be.reads)
	}
	// A job finishing in a cached engagement updates the cache without a read.
	p.Save(outcome("j9", "e0", t0.Add(time.Hour), 1, true))
	if got := p.ByEngagement("e0"); len(got) != 2 || got[0].JobID != "j9" {
		t.Fatalf("cached engagement after a new job: %d outcomes", len(got))
	}
	if be.reads != 3 {
		t.Fatalf("new job in a cached engagement must not re-read: %d reads", be.reads)
	}
}

func TestPersistentOutcomesVersionBumps(t *testing.T) {
	p, _ := NewPersistentOutcomes(newMemBackend(), 0)
	v0 := p.Version("e")
	p.Save(outcome("j", "e", time.Now(), 1, false))
	v1 := p.Version("e")
	p.Save(outcome("j", "e", time.Now(), 1, true))
	if !(v0 < v1 && v1 < p.Version("e")) {
		t.Fatal("every save must change the engagement's version")
	}
}

func TestEncodeOutcomeRoundTripAndShrinks(t *testing.T) {
	o := outcome("j", "e", time.Now(), 500, true)
	enc, err := EncodeOutcome(o, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeOutcome(enc, nil, "", o.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Results) != 500 || dec.Results[7].Data["title"] != "t" || !dec.StartedAt.Equal(o.StartedAt) {
		t.Fatal("round trip changed the outcome")
	}
	raw, _ := jsonSize(o)
	if len(enc)*4 > raw {
		t.Errorf("compressed %d bytes from %d: expected at least 4x", len(enc), raw)
	}
}

func jsonSize(o Outcome) (int, error) {
	b, err := json.Marshal(o)
	return len(b), err
}

// fakeSealer stands in for the tenant key ring: it tags the value with the
// tenant and record so a mismatch is caught.
type fakeSealer struct{}

func (fakeSealer) Seal(tenant, record string, p []byte) (string, error) {
	return "sealed:" + tenant + "|" + record + "|" + string(p), nil
}

func (fakeSealer) Open(tenant, record, s string) ([]byte, error) {
	prefix := "sealed:" + tenant + "|" + record + "|"
	if !strings.HasPrefix(s, prefix) {
		return nil, errors.New("wrong tenant or record")
	}
	return []byte(strings.TrimPrefix(s, prefix)), nil
}

func TestEncodeOutcomeSealed(t *testing.T) {
	o := Outcome{JobID: "j1", Engagement: "e1", Module: "m", StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC()}
	enc, err := EncodeOutcome(o, fakeSealer{}, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(enc), "sealed:t1|outcome/j1|") {
		t.Fatalf("not sealed: %q", enc[:20])
	}
	if got, err := DecodeOutcome(enc, fakeSealer{}, "t1", "j1"); err != nil || got.JobID != "j1" {
		t.Fatalf("open: %v %+v", err, got)
	}
	if _, err := DecodeOutcome(enc, fakeSealer{}, "t2", "j1"); err == nil {
		t.Fatal("opened with another tenant")
	}
	if _, err := DecodeOutcome(enc, nil, "", "j1"); err == nil {
		t.Fatal("decoded a sealed value with encryption off")
	}
	// A value stored before encryption was on stays readable with it on.
	plain, _ := EncodeOutcome(o, nil, "")
	if got, err := DecodeOutcome(plain, fakeSealer{}, "t1", "j1"); err != nil || got.JobID != "j1" {
		t.Fatalf("plain with sealer: %v", err)
	}
}

// The time-left estimate learns from finished jobs, as MemOutcomes does.
func TestPersistentOutcomesEstimates(t *testing.T) {
	p, err := NewPersistentOutcomes(newMemBackend(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1000, 0)
	running := Outcome{JobID: "j2", Engagement: "e", Module: "m", Allowed: []module.Target{{}}, StartedAt: t0}
	if e := p.Estimate(running, t0.Add(time.Second)); e.State != eta.Estimating {
		t.Fatalf("no history yet: got %q", e.State)
	}
	for i := range 3 {
		id := fmt.Sprintf("old%d", i)
		p.Save(Outcome{JobID: id, Engagement: "e", Module: "m", Allowed: []module.Target{{}}, StartedAt: t0.Add(-time.Hour), FinishedAt: t0.Add(-time.Hour + time.Minute)})
	}
	if e := p.Estimate(running, t0.Add(time.Second)); e.State != eta.Running {
		t.Fatalf("with history: got %q", e.State)
	}
	if e := p.Estimate(Outcome{FinishedAt: t0}, t0); e.State != eta.Done {
		t.Fatalf("finished: got %q", e.State)
	}
}
