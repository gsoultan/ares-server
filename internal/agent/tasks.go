// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package agent

import "github.com/gsoultan/ares-server/internal/uuid"

// Task is one authorized unit of work queued for an agent. The agent runs it
// only if its module's capability group is on the agent's allow-list, and it
// re-enforces the engagement scope locally before any target is touched (the
// double barrier). ScopeSnapshot is the serialized engagement scope; Params is
// capability-specific (e.g. the target list).
type Task struct {
	ID            string `json:"id"`
	Module        string `json:"module"`
	ScopeSnapshot []byte `json:"scopeSnapshot"`
	Params        []byte `json:"params"`
}

// EnqueueTask queues a task for an agent and returns its id. The caller has
// already authorized it (engagement runnable, agent bound, module allowed).
func (r *Registry) EnqueueTask(agentID string, t Task) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok || a.State != StateActive {
		return "", ErrUnknownAgent
	}
	if t.ID == "" {
		t.ID = uuid.NewV7()
	}
	if r.tasks == nil {
		r.tasks = map[string][]Task{}
	}
	r.tasks[agentID] = append(r.tasks[agentID], t)
	return t.ID, nil
}

// DrainTasks returns and clears the agent's queued tasks, for delivery over the
// PullTasks stream.
func (r *Registry) DrainTasks(agentID string) []Task {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.tasks[agentID]
	delete(r.tasks, agentID)
	return out
}

// PendingTasks reports how many tasks are queued for an agent.
func (r *Registry) PendingTasks(agentID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tasks[agentID])
}
