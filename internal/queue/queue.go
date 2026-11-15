// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package queue is a simple in-process job queue. In step 1 the control plane
// and workers run in one process, so the queue is a buffered channel. The same
// interface fronts a durable queue (Postgres or NATS) when workers move to
// separate processes.
package queue

import (
	"encoding/json"
	"errors"

	"github.com/gsoultan/ares/module"
)

// Job is one unit of work: run a named module against a set of targets for an
// engagement. Params carries optional, module-specific configuration for
// modules that implement module.Configurable.
type Job struct {
	ID           string          `json:"id"`
	EngagementID string          `json:"engagementId"`
	Module       string          `json:"module"`
	Actor        string          `json:"actor"`
	Targets      []module.Target `json:"targets"`
	Params       json.RawMessage `json:"params,omitempty"`
}

// Queue is a buffered, concurrency-safe job channel.
type Queue struct {
	ch chan Job
}

// New returns a queue that buffers up to size jobs.
func New(size int) *Queue {
	if size < 1 {
		size = 1
	}
	return &Queue{ch: make(chan Job, size)}
}

// Enqueue adds a job, blocking only if the buffer is full.
func (q *Queue) Enqueue(j Job) { q.ch <- j }

// ErrFull is returned by TryEnqueue when the queue is at capacity.
var ErrFull = errors.New("queue: full")

// TryEnqueue adds a job without blocking, or returns ErrFull. Request handlers
// use it so a full queue answers "try again later" at once instead of holding
// the request (and its goroutine and connection) until a worker frees a slot.
func (q *Queue) TryEnqueue(j Job) error {
	select {
	case q.ch <- j:
		return nil
	default:
		return ErrFull
	}
}

// C exposes the channel workers consume from.
func (q *Queue) C() <-chan Job { return q.ch }

// Close stops the queue; consumers ranging over C will finish.
func (q *Queue) Close() { close(q.ch) }
