// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package engagement

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/uuid"
	"github.com/gsoultan/ares/module"
)

// Test intensity and consent.
//
// Every engagement allows tests up to one consent level (the engine's
// module.ConsentLevel). Level 1, safe proof, is the default and needs nothing.
// Level 2, active confirmation, is a per-engagement opt-in. Level 3, intrusive
// but recoverable, also needs a recorded approval per technique and per target
// before each run: an approval is spent by the run it allows, so a second run
// needs a second approval. There is no level above 3, so nothing irreversible
// can be allowed, approved or run.

// Approval is one recorded, single-use approval for an intrusive (level 3)
// technique against one target.
type Approval struct {
	ID         string    `json:"id"`
	Module     string    `json:"module"`
	Target     string    `json:"target"` // module.Target.String() of the approved target
	ApprovedBy string    `json:"approvedBy"`
	How        string    `json:"how,omitempty"` // how it was given (signed change request, email…)
	Note       string    `json:"note,omitempty"`
	ApprovedAt time.Time `json:"approvedAt"`
	// JobID is set when a run uses the approval; a used approval cannot be used
	// again.
	JobID  string    `json:"jobId,omitempty"`
	UsedAt time.Time `json:"usedAt,omitzero"`
	// Withdrawn is set when the approval was taken back before it was used.
	Withdrawn bool `json:"withdrawn,omitempty"`
}

// Used reports whether a run has already spent the approval.
func (a Approval) Used() bool { return a.JobID != "" }

// Usable reports whether the approval can still allow a run.
func (a Approval) Usable() bool { return !a.Used() && !a.Withdrawn }

// ConsentRecord is an engagement's test intensity and its intrusive-test
// approvals. A nil record means the default: safe proof only, no approvals.
type ConsentRecord struct {
	Level     module.ConsentLevel `json:"level"`
	SetBy     string              `json:"setBy,omitempty"`
	SetAt     time.Time           `json:"setAt,omitzero"`
	Approvals []Approval          `json:"approvals,omitempty"`
}

// consentMu serialises consent changes: handlers record approvals while the
// worker reserves them for a run.
var consentMu sync.Mutex

var (
	// ErrLevelRange is returned for a level outside 1–3.
	ErrLevelRange = errors.New("test intensity must be 1 (safe proof), 2 (active confirmation) or 3 (intrusive)")
	// ErrAboveIntensity is returned when a technique needs more than the
	// engagement allows.
	ErrAboveIntensity = errors.New("this test needs a higher test intensity than the engagement allows")
	// ErrNeedsApproval is returned when an intrusive technique has no usable
	// approval for a target.
	ErrNeedsApproval = errors.New("this intrusive test needs a recorded approval for every target before it runs")
)

// TestLevel returns the highest consent level the engagement allows.
func (e *Engagement) TestLevel() module.ConsentLevel {
	consentMu.Lock()
	defer consentMu.Unlock()
	return e.testLevel()
}

func (e *Engagement) testLevel() module.ConsentLevel {
	if e.Consent == nil || e.Consent.Level < module.LevelSafeProof {
		return module.LevelSafeProof
	}
	return e.Consent.Level
}

// ConsentSnapshot returns a copy of the consent record, safe to read while
// approvals change.
func (e *Engagement) ConsentSnapshot() ConsentRecord {
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent == nil {
		return ConsentRecord{Level: module.LevelSafeProof}
	}
	cp := *e.Consent
	cp.Level = e.testLevel()
	cp.Approvals = append([]Approval(nil), e.Consent.Approvals...)
	return cp
}

// SetTestLevel sets the highest level the engagement allows and logs it.
// Lowering the level withdraws every approval that is not yet used.
func (e *Engagement) SetTestLevel(level module.ConsentLevel, actor string) error {
	if level < module.LevelSafeProof || level > module.MaxLevel {
		return ErrLevelRange
	}
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent == nil {
		e.Consent = &ConsentRecord{}
	}
	prev := e.testLevel()
	e.Consent.Level = level
	e.Consent.SetBy = actor
	e.Consent.SetAt = time.Now()
	withdrawn := 0
	if level < module.LevelIntrusive {
		for i := range e.Consent.Approvals {
			if e.Consent.Approvals[i].Usable() {
				e.Consent.Approvals[i].Withdrawn = true
				withdrawn++
			}
		}
	}
	detail := fmt.Sprintf("from %s to %s", prev, level)
	if withdrawn > 0 {
		detail += fmt.Sprintf("; %d unused approval(s) withdrawn", withdrawn)
	}
	e.Audit.Append(actor, "intensity-set", e.ID, detail)
	return nil
}

// Approve records a single-use approval for an intrusive technique against one
// target. The engagement must allow intrusive tests and the target must be in
// scope; the approval is written to the activity log.
func (e *Engagement) Approve(mod string, target module.Target, approvedBy, how, note string) (Approval, error) {
	if strings.TrimSpace(mod) == "" {
		return Approval{}, errors.New("an approval names the test it allows")
	}
	if strings.TrimSpace(approvedBy) == "" {
		return Approval{}, errors.New("an approval names the person who gave it")
	}
	if ok, reason := e.CanRun(); !ok {
		return Approval{}, errors.New(reason)
	}
	if ok, reason := e.Scope.AllowAt(target, time.Now()); !ok {
		return Approval{}, fmt.Errorf("the target is not in scope: %s", reason)
	}
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.testLevel() < module.LevelIntrusive {
		return Approval{}, ErrAboveIntensity
	}
	a := Approval{
		ID:         uuid.NewV7(),
		Module:     mod,
		Target:     target.String(),
		ApprovedBy: strings.TrimSpace(approvedBy),
		How:        strings.TrimSpace(how),
		Note:       strings.TrimSpace(note),
		ApprovedAt: time.Now(),
	}
	e.Consent.Approvals = append(e.Consent.Approvals, a)
	e.Audit.Append(a.ApprovedBy, "technique-approved", a.Target, mod+" · single use · "+a.ID)
	return a, nil
}

// Decline records that an intrusive technique was looked at and not allowed.
// Nothing runs; the decision is only logged.
func (e *Engagement) Decline(mod string, target module.Target, actor, note string) {
	detail := mod
	if strings.TrimSpace(note) != "" {
		detail += " · " + strings.TrimSpace(note)
	}
	e.Audit.Append(actor, "technique-declined", target.String(), detail)
}

// Withdraw takes back an approval that has not been used.
func (e *Engagement) Withdraw(approvalID, actor string) error {
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent != nil {
		for i := range e.Consent.Approvals {
			a := &e.Consent.Approvals[i]
			if a.ID != approvalID {
				continue
			}
			if !a.Usable() {
				return errors.New("that approval was already used or withdrawn")
			}
			a.Withdrawn = true
			e.Audit.Append(actor, "approval-withdrawn", a.Target, a.Module+" · "+a.ID)
			return nil
		}
	}
	return errors.New("unknown approval")
}

// ConsentGate decides whether a job may run a technique of the given level
// against the targets. For an intrusive technique it reserves one usable
// approval per target for the job (spending them) and returns them. A job id
// that already holds approvals for every target is accepted again, so the
// dispatch check and the worker's own check agree.
func (e *Engagement) ConsentGate(mod string, level module.ConsentLevel, targets []module.Target, jobID string) ([]Approval, error) {
	if level <= module.LevelSafeProof {
		return nil, nil
	}
	if level > module.MaxLevel {
		return nil, ErrLevelRange
	}
	consentMu.Lock()
	defer consentMu.Unlock()
	if level > e.testLevel() {
		return nil, ErrAboveIntensity
	}
	if level < module.LevelIntrusive {
		return nil, nil
	}
	if len(targets) == 0 {
		return nil, ErrNeedsApproval
	}
	// Pick one approval per target without changing anything, so a refusal
	// leaves every approval as it was.
	picked := make([]int, 0, len(targets))
	taken := map[int]bool{}
	for _, t := range targets {
		key := t.String()
		idx := -1
		for i, a := range e.Consent.Approvals {
			if taken[i] || a.Module != mod || a.Target != key {
				continue
			}
			if a.JobID == jobID {
				idx = i
				break
			}
			if idx < 0 && a.Usable() {
				idx = i
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("%w (none for %s)", ErrNeedsApproval, key)
		}
		taken[idx] = true
		picked = append(picked, idx)
	}
	now := time.Now()
	out := make([]Approval, 0, len(picked))
	for _, i := range picked {
		a := &e.Consent.Approvals[i]
		if a.JobID == "" {
			a.JobID = jobID
			a.UsedAt = now
			e.Audit.Append(a.ApprovedBy, "approval-used", a.Target, mod+" · job "+jobID)
		}
		out = append(out, *a)
	}
	return out, nil
}

// ApprovalsForJob returns the approvals a job used, for labelling its
// findings.
func (e *Engagement) ApprovalsForJob(jobID string) []Approval {
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent == nil || jobID == "" {
		return nil
	}
	var out []Approval
	for _, a := range e.Consent.Approvals {
		if a.JobID == jobID {
			out = append(out, a)
		}
	}
	return out
}

// ConsentForStore returns a copy of the consent record for a store to persist,
// or nil when the engagement still has the default.
func (e *Engagement) ConsentForStore() *ConsentRecord {
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent == nil {
		return nil
	}
	cp := *e.Consent
	cp.Approvals = append([]Approval(nil), e.Consent.Approvals...)
	return &cp
}

// ReleaseJob gives back the approvals a job reserved when the job never ran
// (the queue was full). It is logged so the trail shows the approval is usable
// again.
func (e *Engagement) ReleaseJob(jobID string) {
	consentMu.Lock()
	defer consentMu.Unlock()
	if e.Consent == nil || jobID == "" {
		return
	}
	for i := range e.Consent.Approvals {
		a := &e.Consent.Approvals[i]
		if a.JobID == jobID {
			a.JobID = ""
			a.UsedAt = time.Time{}
			e.Audit.Append("system", "approval-released", a.Target, a.Module+" · job "+jobID+" did not start")
		}
	}
}
