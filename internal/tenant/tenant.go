// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package tenant models a client workspace: the isolation boundary that owns a
// set of engagements. A security team runs engagements for many clients, and
// one client's engagements, scope, findings and audit trail must never be
// visible from another's workspace. That isolation is enforced at the store and
// the API boundary, not left to convention.
package tenant

import "time"

const (
	// DefaultID is the built-in workspace. Engagements created without an
	// explicit tenant, and engagements persisted before tenancy existed, belong
	// to it, so a single-client deployment needs no setup and older data stays
	// reachable. It is a reserved, well-known UUIDv7-form value (a zero
	// timestamp) so every id in the system is a UUID, yet the default workspace
	// stays resolvable without a lookup.
	DefaultID = "00000000-0000-7000-8000-000000000000"
	// DefaultName is the display name of the default workspace.
	DefaultName = "Default workspace"
)

// Tenant is one client workspace.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Resolve maps an empty workspace id to the default workspace, so callers that
// do not supply a tenant land on the built-in one. A non-empty id is returned
// unchanged (its existence is validated by the store, not here).
func Resolve(id string) string {
	if id == "" {
		return DefaultID
	}
	return id
}
