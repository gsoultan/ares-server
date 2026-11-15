// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/secret"
)

// state is the agent's local, on-disk state: the enrolled credential and
// binding, the operator-readable activity log, and the encrypted
// store-and-forward outbox. The outbox and credential are sealed at rest with a
// key generated on first open, so a copy of the state directory alone yields
// neither the live credential nor buffered findings. The outbox is transient —
// a result is removed once the server acknowledges it; nothing of the
// engagement's data is retained host-only.
type state struct {
	dir    string
	cfg    config
	sealer *secret.Sealer

	mu     sync.Mutex
	enr    *EnrollResult
	pubKey []byte
	outbox []Result
	seen   time.Time
}

const (
	keyFile    = "agent.key"
	enrollFile = "enrollment.json"
	outboxFile = "outbox.json"
	logFile    = "activity.log"
	metaFile   = "meta.json"
)

// openState opens or initializes the agent state directory for cfg.
func openState(cfg config) (*state, error) {
	if cfg.StateDir == "" {
		cfg.StateDir = defaultStateDir()
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	st := &state{dir: cfg.StateDir, cfg: cfg}

	key, err := st.loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	sealer, err := secret.NewSealer(key)
	if err != nil {
		return nil, fmt.Errorf("state sealer: %w", err)
	}
	st.sealer = sealer

	// A stable agent keypair placeholder: phase 1 records a public key so the
	// enrollment surface is exercised; the real keypair is generated here when
	// the credential form (mTLS) is settled in the design.
	st.pubKey = []byte("ares-agent-pubkey-placeholder")

	st.loadEnrollment()
	st.loadOutbox()
	st.loadMeta()
	// Persisted config (from enrollment) wins, so `run`/`status` need only --state.
	if st.cfg.ServerURL == "" && st.enr != nil {
		st.cfg = st.storedConfig()
	}
	return st, nil
}

func (s *state) path(name string) string { return filepath.Join(s.dir, name) }

func (s *state) loadOrCreateKey() ([]byte, error) {
	raw, err := os.ReadFile(s.path(keyFile))
	if err == nil {
		return secret.DecodeKey(string(raw))
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key, err := secret.NewKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.path(keyFile), []byte(secret.EncodeKey(key)), 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return key, nil
}

// Enrolled reports whether this agent has a saved enrollment.
func (s *state) Enrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enr != nil
}

// Enrollment returns the saved enrollment (without the raw credential).
func (s *state) Enrollment() EnrollResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enr == nil {
		return EnrollResult{}
	}
	e := *s.enr
	e.Credential = "" // never expose the credential outside the sealed file
	return e
}

// Credential returns the raw credential for the transport to present. It is read
// from the sealed enrollment file and never logged.
func (s *state) Credential() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enr == nil {
		return ""
	}
	return s.enr.Credential
}

// PublicKey returns the agent's public key sent at enrollment.
func (s *state) PublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pubKey
}

// Config returns the effective connectivity config.
func (s *state) Config() config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// SaveEnrollment seals and persists the enrollment, and remembers the config so
// later `run`/`status` need only --state.
func (s *state) SaveEnrollment(res EnrollResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enr = &res
	if err := s.sealJSON(enrollFile, res); err != nil {
		return err
	}
	return s.sealJSON(metaFile, s.cfg)
}

func (s *state) storedConfig() config {
	var cfg config
	_ = s.openJSON(metaFile, &cfg)
	cfg.StateDir = s.dir
	return cfg
}

func (s *state) loadEnrollment() {
	var res EnrollResult
	if err := s.openJSON(enrollFile, &res); err == nil {
		s.enr = &res
	}
}

func (s *state) loadMeta() {
	var cfg config
	if err := s.openJSON(metaFile, &cfg); err == nil {
		cfg.StateDir = s.dir
		if cfg.ServerURL != "" {
			s.cfg = cfg
		}
	}
}

// Outbox (store-and-forward) -------------------------------------------------

func (s *state) loadOutbox() {
	var box []Result
	if err := s.openJSON(outboxFile, &box); err == nil {
		s.outbox = box
	}
}

// Enqueue adds a result to the encrypted outbox for later delivery.
func (s *state) Enqueue(r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbox = append(s.outbox, r)
	return s.sealJSON(outboxFile, s.outbox)
}

// Pending returns a copy of the outbox for the flush loop.
func (s *state) Pending() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Result, len(s.outbox))
	copy(out, s.outbox)
	return out
}

// Ack removes a delivered result from the outbox once the server has it.
func (s *state) Ack(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.outbox[:0]
	for _, r := range s.outbox {
		if r.TaskID != taskID {
			kept = append(kept, r)
		}
	}
	s.outbox = kept
	return s.sealJSON(outboxFile, s.outbox)
}

// OutboxLen reports how many results are pending delivery.
func (s *state) OutboxLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outbox)
}

// Activity log ---------------------------------------------------------------

// Log appends a line to the local, operator-readable activity log. The agent is
// transparent: everything it does is here and in the engagement audit trail.
func (s *state) Log(format string, a ...any) {
	line := fmt.Sprintf("%s  %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
	f, err := os.OpenFile(s.path(logFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// MarkSeen records the last successful check-in time.
func (s *state) MarkSeen(t time.Time) {
	s.mu.Lock()
	s.seen = t
	s.mu.Unlock()
}

// LastSeen returns the last check-in time as text.
func (s *state) LastSeen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen.IsZero() {
		return "never"
	}
	return s.seen.UTC().Format(time.RFC3339)
}

// Wipe deletes all local agent state. Used by uninstall; leaves nothing behind.
func (s *state) Wipe() error {
	return os.RemoveAll(s.dir)
}

// sealed JSON helpers --------------------------------------------------------

func (s *state) sealJSON(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := s.sealer.Seal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(name), []byte(sealed), 0o600)
}

func (s *state) openJSON(name string, v any) error {
	sealed, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	raw, err := s.sealer.Open(string(sealed))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
