// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package main

import (
	"context"
	"math/rand"
	"time"
)

const (
	heartbeatEvery = 30 * time.Second
	backoffMin     = 1 * time.Second
	backoffMax     = 2 * time.Minute
)

// agentLoop is the agent's main run loop: it keeps a persistent outbound link
// up (heartbeat + reconnect with backoff), flushes the store-and-forward outbox
// whenever the link is healthy, and runs the tasks the server dispatches —
// always within the engagement scope and the capability allow-list. Phase 1
// wires the control flow; the task handlers that run live capabilities land once
// the design is signed off.
type agentLoop struct {
	state     *state
	transport Transport
}

// Run drives the loop until ctx is cancelled or the agent is told to deregister.
func (l *agentLoop) Run(ctx context.Context) error {
	backoff := backoffMin
	for {
		if ctx.Err() != nil {
			return nil
		}
		dir, err := l.cycle(ctx)
		switch {
		case dir == DirectiveDeregister:
			l.state.Log("server directive: deregister — tearing down")
			if transport, terr := newTransport(l.state.Config(), l.state.Credential); terr == nil {
				c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_ = transport.Deregister(c, "operator-revoke")
				cancel()
			}
			return l.state.Wipe()
		case dir == DirectiveStop:
			l.state.Log("server directive: stop — engagement paused/halted; holding")
		case err != nil:
			// The link dropped or the server is unreachable. This is normal behind
			// NAT/proxies; back off and reconnect. Results stay safe in the outbox.
			l.state.Log("link error (%v); reconnecting in %s", err, backoff)
			if !sleep(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		// Healthy cycle: reset backoff and wait for the next heartbeat tick.
		backoff = backoffMin
		if !sleep(ctx, heartbeatEvery) {
			return nil
		}
	}
}

// cycle runs one heartbeat, flushes the outbox, and drains any dispatched tasks.
// It returns the server's directive so Run can stop or tear down.
func (l *agentLoop) cycle(ctx context.Context) (Directive, error) {
	hbCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	dir, caps, err := l.transport.Heartbeat(hbCtx)
	if err != nil {
		return DirectiveContinue, err
	}
	l.state.MarkSeen(time.Now())
	if len(caps) > 0 {
		l.state.Log("capability allow-list updated: %v", caps)
	}
	if dir != DirectiveContinue {
		return dir, nil
	}

	l.flushOutbox(ctx)
	l.drainTasks(ctx)
	return DirectiveContinue, nil
}

// flushOutbox forwards every buffered result, removing each as the server
// acknowledges it. Delivery is idempotent on task id, so a retry after a dropped
// link never double-reports.
func (l *agentLoop) flushOutbox(ctx context.Context) {
	for _, r := range l.state.Pending() {
		if ctx.Err() != nil {
			return
		}
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := l.transport.PushResults(c, r)
		cancel()
		if err != nil {
			l.state.Log("outbox: deferring %s (%v)", r.TaskID, err)
			return // keep ordering; try again next cycle
		}
		_ = l.state.Ack(r.TaskID)
		l.state.Log("outbox: delivered %s", r.TaskID)
	}
}

// drainTasks pulls dispatched tasks and handles them. In phase 1 the handler is
// a stub that records the task; the capability runners (scope-gated, inert) are
// added once the design is signed off.
func (l *agentLoop) drainTasks(ctx context.Context) {
	tasks := make(chan Task, 4)
	pullCtx, cancel := context.WithTimeout(ctx, heartbeatEvery)
	defer cancel()
	go func() { _ = l.transport.PullTasks(pullCtx, tasks) }()

	for {
		select {
		case <-pullCtx.Done():
			return
		case t, ok := <-tasks:
			if !ok {
				return
			}
			l.handleTask(t)
		}
	}
}

// handleTask runs one authorized task. Phase-1 stub: it records receipt and
// enqueues a placeholder result so the store-and-forward path is exercised. No
// live capability runs yet.
func (l *agentLoop) handleTask(t Task) {
	l.state.Log("task %s: capability %q received (phase-1 skeleton: not executed)", t.TaskID, t.Capability)
	_ = l.state.Enqueue(Result{
		TaskID: t.TaskID,
		Error:  "capability not yet enabled (phase-1 skeleton)",
	})
}

// sleep waits d, returning false if the context is cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// nextBackoff doubles the delay up to the cap, with jitter to avoid a
// thundering herd of agents reconnecting in lockstep.
func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > backoffMax {
		d = backoffMax
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 4)) //nolint:gosec // non-crypto jitter
	return d - jitter
}
