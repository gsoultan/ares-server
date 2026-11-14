// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package server is the root of the Ares server: the multi-tenant control
// plane that owns workspaces, accounts and sessions, sealed secrets, the
// settings store, first-run setup, the datastore, job management and the
// operator-facing API and web UI.
//
// The testing engine itself (recon, the check and attack modules, the
// permission gate and forensics) lives in github.com/gsoultan/ares and is
// imported here as a Go library. See README.md and docs/split-plan.md.
package server
