// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package worker

import (
	"context"
	"testing"

	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/queue"
	"github.com/gsoultan/ares/module"
	"github.com/gsoultan/ares/websession"
)

// fakeProvider hands back a fixed session (or error) and records that it was asked.
type fakeProvider struct {
	sess   *websession.Session
	err    error
	called bool
}

func (f *fakeProvider) SessionFor(ctx context.Context, eng *engagement.Engagement) (*websession.Session, error) {
	f.called = true
	return f.sess, f.err
}

// sessionModule records whether the context it ran under carried a session.
type sessionModule struct{ sawSession bool }

func (m *sessionModule) Name() string { return "sessionprobe" }
func (m *sessionModule) Run(ctx context.Context, _ module.Scope, _ []module.Target, out chan<- module.Result) error {
	if websession.From(ctx) != nil {
		m.sawSession = true
	}
	return nil
}

func authSetup(t *testing.T, mod module.Module) (*Processor, engagement.Store) {
	t.Helper()
	reg := module.NewRegistry()
	if err := reg.Register(mod); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := engagement.NewMemStore()
	return NewProcessor(reg, store), store
}

func authorizedEng(t *testing.T, store engagement.Store) *engagement.Engagement {
	t.Helper()
	eng, err := store.Create("", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = eng.Scope.AddInScope("example.com")
	if err := eng.Authorize(engagement.Authorization{Document: "auth.pdf", ApprovedBy: "lead"}); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return eng
}

// TestSessionReachesModule proves a provider's session is attached to the
// context the module runs under.
func TestSessionReachesModule(t *testing.T) {
	mod := &sessionModule{}
	proc, store := authSetup(t, mod)
	eng := authorizedEng(t, store)

	sess, err := websession.NewSession(context.Background(), websession.Credential{Bearer: "t"},
		[]string{"example.com"}, 0)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	fp := &fakeProvider{sess: sess}
	proc.WithAuth(fp)

	out := proc.Process(context.Background(), queue.Job{
		ID: "j1", EngagementID: eng.ID, Module: "sessionprobe", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error != "" {
		t.Fatalf("job errored: %s", out.Error)
	}
	if !fp.called {
		t.Fatal("provider was not consulted")
	}
	if !mod.sawSession {
		t.Fatal("module did not run under the authenticated session")
	}
}

// TestNoProviderRunsAnonymously proves that without a provider the module runs
// with no session — the unchanged default.
func TestNoProviderRunsAnonymously(t *testing.T) {
	mod := &sessionModule{}
	proc, store := authSetup(t, mod)
	eng := authorizedEng(t, store)

	out := proc.Process(context.Background(), queue.Job{
		ID: "j1", EngagementID: eng.ID, Module: "sessionprobe", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error != "" {
		t.Fatalf("job errored: %s", out.Error)
	}
	if mod.sawSession {
		t.Fatal("module saw a session with no provider configured")
	}
}

// TestProviderErrorFallsBackToAnonymous proves a failed session build does not
// fail the job: the probe runs anonymously and the skip is audited.
func TestProviderErrorFallsBackToAnonymous(t *testing.T) {
	mod := &sessionModule{}
	proc, store := authSetup(t, mod)
	eng := authorizedEng(t, store)
	proc.WithAuth(&fakeProvider{err: context.DeadlineExceeded})

	out := proc.Process(context.Background(), queue.Job{
		ID: "j1", EngagementID: eng.ID, Module: "sessionprobe", Actor: "op",
		Targets: []module.Target{{Host: "example.com"}},
	})
	if out.Error != "" {
		t.Fatalf("job should not fail when the session cannot be built: %s", out.Error)
	}
	if mod.sawSession {
		t.Fatal("module should have run anonymously after a provider error")
	}
}
