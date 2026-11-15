// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package agent is the server-side registry for Ares agents: the transparent,
// authorized components an operator deploys inside a target's network or on a
// host to run inside-the-perimeter checks (see ares-design/agent-design.md and
// agent-prd.md). It is NOT an implant framework — every agent is visible,
// scope-bound, revocable, and cleanly removable.
//
// This package owns enrollment (minting and redeeming one-time, engagement-
// scoped enrollment tokens), the durable agent records, and the binding and
// revocation checks that keep an agent inside its own engagement and tenant. It
// holds no transport: the gRPC AgentService (proto/ares/v1/agent.proto) calls
// into it. Like auth sessions, the raw enrollment token and the raw agent
// credential are returned once and never stored — only their SHA-256 hashes are
// kept, so a store disclosure hands out neither.
package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gsoultan/ares-server/internal/uuid"
)

// DefaultEnrollTokenTTL is how long a freshly minted enrollment token can be
// redeemed before it expires. Enrollment is an operator-driven, in-person step,
// so the window is deliberately short.
const DefaultEnrollTokenTTL = 1 * time.Hour

// Heartbeat is the agent's check-in cadence. StaleAfter is how long without a
// heartbeat before an agent is shown as "not heard from" in the operator UI
// (ten missed 30s beats). It does not revoke the agent; it only flags it.
const (
	HeartbeatEvery = 30 * time.Second
	StaleAfter     = 5 * time.Minute
)

// State is an agent's lifecycle state.
type State string

const (
	// StateActive is an enrolled, non-revoked agent.
	StateActive State = "active"
	// StateRevoked is an agent whose credential has been revoked (by the
	// operator, by engagement completion/halt, or by uninstall). A revoked
	// agent's calls are refused and it is told to tear down.
	StateRevoked State = "revoked"
)

// HostFacts is the non-identifying host context an agent reports at enrollment,
// shown on the operator's "Agents" view so it is always clear what is deployed
// where. It carries no scan data.
type HostFacts struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agentVersion"`
	// IP is the agent's own interface address, shown in the UI. SegmentCIDRs is
	// the segment(s) it sits on. Both are the agent's own context — no scan data.
	IP           string   `json:"ip,omitempty"`
	SegmentCIDRs []string `json:"segmentCidrs,omitempty"`
}

// Consent is the required record of the host owner's permission for an agent,
// captured when the operator mints the install key (the "Add an agent —
// permission" step) and carried for the agent's whole life. The agent is
// transparent by design: the owner knows, and this record shows on the agent,
// in the activity log, and in the report.
type Consent struct {
	Who                 string    `json:"who"`                           // who gave permission (name/role)
	How                 string    `json:"how"`                           // how it was given (e.g. "signed authorization letter")
	AuthFileFingerprint string    `json:"authFileFingerprint,omitempty"` // hash of the attached authorization document
	RecordedBy          string    `json:"recordedBy"`                    // operator account that recorded it
	EndsAt              time.Time `json:"endsAt,omitempty"`              // authorization end
	At                  time.Time `json:"at"`
}

// Valid reports whether a consent record carries the minimum: who agreed, how,
// and who recorded it. Enrollment requires it — an agent is never minted without
// a permission record.
func (c Consent) Valid() bool {
	return c.Who != "" && c.How != "" && c.RecordedBy != ""
}

// Agent is the durable record of one enrolled agent, bound to exactly one
// engagement and tenant for its whole life.
type Agent struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenantId"`
	EngagementID string    `json:"engagementId"`
	State        State     `json:"state"`
	Host         HostFacts `json:"host"`
	PublicKey    []byte    `json:"publicKey"`
	// Capabilities is the per-agent allow-list: the only capabilities the agent
	// may run. Anything off this list is refused server-side and agent-side.
	Capabilities []string `json:"capabilities"`
	// Consent is the host owner's permission record, required to enroll.
	Consent Consent `json:"consent"`
	// CurrentCapability names the capability the agent is running right now, so
	// the UI can show "running a check"; empty when idle.
	CurrentCapability string    `json:"currentCapability,omitempty"`
	EnrolledAt        time.Time `json:"enrolledAt"`
	LastSeen          time.Time `json:"lastSeen"`
	RevokedAt         time.Time `json:"revokedAt,omitempty"`
}

// Status is the agent's display status for the UI, derived from its state, its
// current activity, and the heartbeat window.
type Status string

const (
	StatusConnected    Status = "connected"      // healthy, idle
	StatusRunningCheck Status = "running_check"  // a capability is in flight
	StatusNotHeardFrom Status = "not_heard_from" // missed the heartbeat window
	StatusRemoved      Status = "removed"        // revoked / removed
)

// Status returns the display status at time now.
func (a *Agent) StatusAt(now time.Time) Status {
	if a.State != StateActive {
		return StatusRemoved
	}
	if now.Sub(a.LastSeen) > StaleAfter {
		return StatusNotHeardFrom
	}
	if a.CurrentCapability != "" {
		return StatusRunningCheck
	}
	return StatusConnected
}

// Stale reports whether the agent has missed the heartbeat window. A revoked
// agent is never "stale" — it is removed.
func (a *Agent) Stale(now time.Time) bool {
	if a.State != StateActive {
		return false
	}
	return now.Sub(a.LastSeen) > StaleAfter
}

// EnrollToken is a one-time, engagement-scoped enrollment token. The raw token
// is returned to the operator once; the store keeps only its hash.
type EnrollToken struct {
	// ID identifies the key for the UI's "unused install keys" list and for
	// Cancel; it is not the secret (the raw key is returned once at mint).
	ID           string   `json:"id"`
	TenantID     string   `json:"tenantId"`
	EngagementID string   `json:"engagementId"`
	Capabilities []string `json:"capabilities"`
	// Consent is the permission record carried onto the enrolled agent.
	Consent   Consent   `json:"consent"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Redeemed is set when the key is spent, so it can never enroll a second
	// agent even within its validity window. Cancelled is set if an operator
	// cancels an unused key.
	Redeemed  bool `json:"redeemed"`
	Cancelled bool `json:"cancelled"`
}

// Usable reports whether the key can still enroll an agent at time now.
func (t EnrollToken) Usable(now time.Time) bool {
	return !t.Redeemed && !t.Cancelled && !t.Expired(now)
}

// Expired reports whether the token is past its expiry.
func (t EnrollToken) Expired(now time.Time) bool { return now.After(t.ExpiresAt) }

// Errors returned by the registry. Enrollment and auth errors are deliberately
// coarse so a caller cannot probe which tokens or agents exist.
var (
	ErrInvalidToken   = errors.New("agent: invalid or expired enrollment token")
	ErrUnknownAgent   = errors.New("agent: unknown or revoked agent")
	ErrNotAuthorized  = errors.New("agent: not authorized for this engagement")
	ErrCapabilityGate = errors.New("agent: capability not on the agent's allow-list")
	ErrConsentMissing = errors.New("agent: a host-owner permission record is required to enroll")
	ErrUnknownKey     = errors.New("agent: unknown install key")
)

// EngagementGate reports whether an engagement is currently open to agent
// activity. It lets the registry refuse enrollment and calls for a completed or
// halted engagement without importing the engagement store directly. The server
// wires it to engagement lookup.
type EngagementGate func(tenantID, engagementID string) bool

// Registry holds agents and enrollment tokens. It is the single place that
// decides whether an agent call is allowed. Safe for concurrent use.
type Registry struct {
	mu          sync.Mutex
	agents      map[string]*Agent      // by agent id
	credentials map[string]string      // credential hash -> agent id
	tokens      map[string]EnrollToken // token hash -> token
	tokensByID  map[string]string      // key id -> token hash (for list/cancel)
	tasks       map[string][]Task      // agent id -> queued tasks
	gate        EngagementGate
	now         func() time.Time // injectable clock for tests
}

// NewRegistry builds an empty registry. gate may be nil (then every engagement
// is treated as open — only for tests); production wiring always supplies one.
func NewRegistry(gate EngagementGate) *Registry {
	return &Registry{
		agents:      map[string]*Agent{},
		credentials: map[string]string{},
		tokens:      map[string]EnrollToken{},
		tokensByID:  map[string]string{},
		gate:        gate,
		now:         time.Now,
	}
}

func (r *Registry) engagementOpen(tenantID, engagementID string) bool {
	if r.gate == nil {
		return true
	}
	return r.gate(tenantID, engagementID)
}

// MintEnrollToken creates a one-time install key for an engagement and returns
// the key id and the raw key (the key is shown to the operator once). The
// engagement must be open and a valid host-owner consent record is required —
// an agent is never created without recorded permission. The capabilities
// become the enrolled agent's allow-list.
func (r *Registry) MintEnrollToken(tenantID, engagementID string, capabilities []string, consent Consent) (id, raw string, err error) {
	if !r.engagementOpen(tenantID, engagementID) {
		return "", "", ErrNotAuthorized
	}
	if !consent.Valid() {
		return "", "", ErrConsentMissing
	}
	raw, err = newSecret()
	if err != nil {
		return "", "", err
	}
	now := r.now()
	if consent.At.IsZero() {
		consent.At = now
	}
	tok := EnrollToken{
		ID:           uuid.NewV7(),
		TenantID:     tenantID,
		EngagementID: engagementID,
		Capabilities: append([]string(nil), capabilities...),
		Consent:      consent,
		CreatedAt:    now,
		ExpiresAt:    now.Add(DefaultEnrollTokenTTL),
	}
	th := hashSecret(raw)
	r.mu.Lock()
	r.tokens[th] = tok
	r.tokensByID[tok.ID] = th
	r.mu.Unlock()
	return tok.ID, raw, nil
}

// CancelEnrollToken cancels an unused install key by id, so the UI's "unused
// install keys" list can withdraw one before it is redeemed. Cancelling a
// redeemed or unknown key is reported; cancelling an already-cancelled key is a
// no-op.
func (r *Registry) CancelEnrollToken(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	th, ok := r.tokensByID[id]
	if !ok {
		return ErrUnknownKey
	}
	tok := r.tokens[th]
	if tok.Redeemed {
		return ErrUnknownKey // already spent — nothing to cancel
	}
	tok.Cancelled = true
	r.tokens[th] = tok
	return nil
}

// ListEnrollTokens returns the unused (usable) install keys for an engagement,
// for the operator's "unused install keys" view. The raw key is never returned —
// only its metadata.
func (r *Registry) ListEnrollTokens(tenantID, engagementID string) []EnrollToken {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []EnrollToken
	for _, tok := range r.tokens {
		if tok.TenantID == tenantID && tok.EngagementID == engagementID && tok.Usable(now) {
			out = append(out, tok)
		}
	}
	return out
}

// Enroll redeems an enrollment token and registers a new agent. It returns the
// agent record and the raw credential the agent presents on every later call
// (returned once, stored only as a hash). The token is spent on success and the
// engagement must still be open.
func (r *Registry) Enroll(rawToken string, pubKey []byte, host HostFacts) (*Agent, string, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	th := hashSecret(rawToken)
	tok, ok := r.tokens[th]
	if !ok || !tok.Usable(now) {
		return nil, "", ErrInvalidToken
	}
	if !r.engagementOpen(tok.TenantID, tok.EngagementID) {
		return nil, "", ErrNotAuthorized
	}

	rawCred, err := newSecret()
	if err != nil {
		return nil, "", err
	}
	a := &Agent{
		ID:           uuid.NewV7(),
		TenantID:     tok.TenantID,
		EngagementID: tok.EngagementID,
		State:        StateActive,
		Host:         host,
		PublicKey:    append([]byte(nil), pubKey...),
		Capabilities: append([]string(nil), tok.Capabilities...),
		Consent:      tok.Consent,
		EnrolledAt:   now,
		LastSeen:     now,
	}
	// Spend the token (single-use) and record the agent + credential.
	tok.Redeemed = true
	r.tokens[th] = tok
	r.agents[a.ID] = a
	r.credentials[hashSecret(rawCred)] = a.ID
	return a.clone(), rawCred, nil
}

// Authenticate resolves a raw credential to its agent and enforces binding: the
// agent must be active and its engagement still open. It is the server
// interceptor's single entry point — it returns the bound agent, so a caller
// can never act for a different engagement or tenant than the one it enrolled
// to.
func (r *Registry) Authenticate(rawCred string) (*Agent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.credentials[hashSecret(rawCred)]
	if !ok {
		return nil, ErrUnknownAgent
	}
	a, ok := r.agents[id]
	if !ok || a.State != StateActive {
		return nil, ErrUnknownAgent
	}
	if !r.engagementOpen(a.TenantID, a.EngagementID) {
		return nil, ErrNotAuthorized
	}
	return a.clone(), nil
}

// Heartbeat marks the agent seen and returns whether it should keep running. A
// revoked agent, or one whose engagement has closed, is told to stop.
func (r *Registry) Heartbeat(agentID string) (keepRunning bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok {
		return false, ErrUnknownAgent
	}
	a.LastSeen = r.now()
	if a.State != StateActive || !r.engagementOpen(a.TenantID, a.EngagementID) {
		return false, nil
	}
	return true, nil
}

// AuthorizeCapability checks that a capability is on the agent's allow-list. The
// agent enforces the same check locally, so there are two barriers.
func (r *Registry) AuthorizeCapability(agentID, capability string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok || a.State != StateActive {
		return ErrUnknownAgent
	}
	for _, c := range a.Capabilities {
		if c == capability {
			return nil
		}
	}
	return ErrCapabilityGate
}

// SetCurrentCapability records what the agent is running right now (empty when
// idle), so the UI can show "running a check". It does not change authorization.
func (r *Registry) SetCurrentCapability(agentID, capability string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[agentID]; ok {
		a.CurrentCapability = capability
	}
}

// Revoke revokes an agent (operator action, engagement halt, or uninstall). Its
// credential stops working immediately and it is told to tear down on next
// contact. Revoking an already-revoked agent is a no-op.
func (r *Registry) Revoke(agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok {
		return ErrUnknownAgent
	}
	if a.State == StateActive {
		a.State = StateRevoked
		a.RevokedAt = r.now()
	}
	// Drop the credential mapping so the raw credential can never authenticate
	// again, even before the record is pruned.
	for h, id := range r.credentials {
		if id == agentID {
			delete(r.credentials, h)
		}
	}
	return nil
}

// Get returns a copy of an agent record.
func (r *Registry) Get(agentID string) (*Agent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok {
		return nil, false
	}
	return a.clone(), true
}

// ListByEngagement returns the agents enrolled to an engagement, for the
// operator's "Agents" view.
func (r *Registry) ListByEngagement(tenantID, engagementID string) []*Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Agent
	for _, a := range r.agents {
		if a.TenantID == tenantID && a.EngagementID == engagementID {
			out = append(out, a.clone())
		}
	}
	return out
}

func (a *Agent) clone() *Agent {
	c := *a
	c.PublicKey = append([]byte(nil), a.PublicKey...)
	c.Capabilities = append([]string(nil), a.Capabilities...)
	return &c
}

// newSecret returns a 256-bit random secret, URL-safe base64. Used for both the
// enrollment token and the agent credential.
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agent: secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashSecret returns the hex SHA-256 of a secret, the key under which it is
// stored. Looking a secret up requires presenting it, so the stored hash alone
// is not a usable credential.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
