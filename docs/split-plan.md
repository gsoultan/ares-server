# Engine / server split: move plan

Status: **executed**, stacked on ares PR #7 (the move PRs are drafts until #7 merges).
Basis: `gsoultan/ares` at PR #7's head (`claude/project-thread-5o2385`,
`6ea4116`), which carries the storm-based Postgres datastore. `main` still has
the older raw-pgx datastore, so the move must be made from PR #7's tree, never
from `main`.

## 1. What the import graph says

Every Go package in `ares` lives under `internal/`, so nothing in it can be
imported from another module today. The in-repo import graph (non-test and
test imports) splits cleanly:

- **No engine package imports a server package.** `scope`, `intel`, `canary`,
  `detection`, `purple`, `remediation`, `module`, `check`, `httpx`, `bounds`,
  `forensics/*` and every `modules/*` package depend only on each other and the
  standard library (plus `x/net` and `sevenzip`).
- No engine test imports a server package either.
- The only place that knows every module by name is `cmd/ares-api/main.go`
  (the `reg.Register(...)` block and the two `SetResolver` calls).

So the cut is a straight line with no cycles to break.

## 2. Classification

### Stays in `ares` (the engine)

| Package | Why it is engine | After the move |
|---|---|---|
| `module` | the plug-in contract (`Module`, `Target`, `Result`, `Scope`, `Registry`) | **public** `ares/module` |
| `scope` | the permission gate; travels with the engine so it can never be used without it | **public** `ares/scope` |
| `canary` | out-of-band collaborator the SSRF / Log4Shell probes report into | **public** `ares/canary` (server runs the listener) |
| `intel` | target profiling and check selection | **public** `ares/intel` |
| `detection` | ATT&CK technique outcome model and scoring (stateless) | **public** `ares/detection` |
| `purple` | purple-team exercise / scenario catalog (reference data) | **public** `ares/purple` |
| `remediation` | fix guidance paired with each finding (reference data) | **public** `ares/remediation` |
| `modules/*` (all 31) | recon, fingerprinting, check and attack modules, apkscan, ipascan, triage… | stay `ares/internal/modules/*` |
| `check` | data-driven check engine and rules | stays internal |
| `httpx` | hardened HTTP client for modules | stays internal |
| `bounds` | rate / budget governor for active modules | stays internal |
| `forensics/archive`, `forensics/wpscan` | archive handling, WordPress analysis | stay internal |
| *new* `engine` | facade that builds a fully wired module registry | **public** `ares/engine` |

### Moves to `ares-server`

| Package / path | Concern |
|---|---|
| `internal/auth` | email + password accounts, roles, sessions |
| `internal/tenant` | workspaces, the isolation boundary |
| `internal/secret` | AES-256-GCM sealed secrets, master key |
| `internal/settings` | per-workspace settings store |
| `internal/setup` | first-run `/setup` wizard and atomic commit |
| `internal/store/stormstore` | embedded file store (Storm over bbolt) |
| `internal/store/pgstore` (+ `model`, `gen/*`) | **storm-based** Postgres datastore from PR #7 |
| `internal/engagement` | engagements, authorization, lifecycle, `Store` interface |
| `internal/audit` | hash-chained, tamper-evident log |
| `internal/queue` | job queue |
| `internal/worker` | job runner; enforces the gate before any module runs |
| `internal/report` | PDF / DOCX / Markdown report rendering |
| `internal/ai` | AI advisory providers (configured through settings) |
| `internal/uuid` | UUIDv7 ids (only server packages use it) |
| `internal/api` | REST control plane |
| `internal/connectapi`, `internal/gen/**`, `proto/`, `buf*.yaml` | gRPC / Connect control plane and its contract |
| `cmd/ares-api` → `cmd/ares-server` | the server binary |
| `web/` | the operator web UI (PWA) |
| `scripts/` | dev, codegen and setup scripts |

Dependencies follow the code: `connectrpc`, `protobuf`, `asdine/storm`,
`gsoultan/storm` and `pgx` leave `ares/go.mod`; `ares` keeps only `x/net` and
`sevenzip`.

## 3. Boundary: Go library, not a separate service

**Recommendation: `ares-server` imports `ares` as a Go library.**

- The engine is stateless and runs in-process today. A module's `Run` takes a
  live `module.Scope`, and the double barrier (the worker checks the gate, then
  every module re-checks it per target) relies on that gate being an in-process
  object. Over gRPC the module side would need its own copy of the scope and
  time window, and a bug in syncing it would weaken the safety core.
- Ares is self-hosted. A library keeps it one binary with one deploy, which the
  `/setup` wizard and the embedded file store are built around.
- Results stream back on a Go channel with no serialisation, no extra auth
  between processes and no new failure modes (timeouts, retries, partial
  results).
- The API to keep stable is small: `engine`, `module`, `scope`, `canary`,
  `intel`, `detection`, `purple`, `remediation`. Everything else stays
  `internal/` in `ares`, so it can change freely.

Trade-offs accepted:

- Releases are coupled through `go.mod`: an engine change reaches the server
  by bumping `github.com/gsoultan/ares` (a tag or pseudo-version). Day to day,
  a `go.work` with both checkouts makes this invisible.
- The engine cannot be scaled or crashed independently. If that is needed
  later, `queue` already anticipates a durable queue, so a separate
  `ares-worker` process that imports the same library can be added without
  changing the boundary. A gRPC engine service stays an option, not a
  prerequisite.
- Both repos are private, so `GOPRIVATE=github.com/gsoultan/*` is needed for
  module fetching in CI and on dev machines.

## 4. The public engine API

New package `github.com/gsoultan/ares/engine`, lifted from the registration
block in `cmd/ares-api/main.go`:

```go
type Options struct {
    CanaryStore  *canary.Store // nil disables the out-of-band probes
    CanaryBase   string        // HTTP base the target calls back to
    CanaryDomain string        // DNS canary domain (Log4Shell); empty = inert
}

// New returns a registry with every engine module registered and the recon
// and apkbackend resolvers wired to it.
func New(opts Options) (*module.Registry, error)
```

The server then only ever names packages from the public list above.

## 5. Move procedure (phase 2, after PR #7 merges)

1. `ares`: `git mv` the public packages from `internal/X` to `X`, add
   `engine/`, rewrite imports, delete the server packages, `cmd/`, `web/`,
   `proto/`, `buf*.yaml`, `scripts/`; `go mod tidy`; build, vet and test green.
   Tag (e.g. `v0.1.0`) so the server can pin it.
2. `ares-server`: copy the server packages with history-free `git` adds,
   rewrite imports to `github.com/gsoultan/ares-server/internal/...` and to the
   public engine packages, replace the registration block with `engine.New`,
   regenerate `internal/gen` with `buf` (the Go package path changes), and
   keep `pgstore/gen` as generated by storm (re-run `storm generate` only if
   the import path inside it changes).
3. Tests that must stay green on the server: audit chain verify and tamper
   detection, auth (hashing, sessions, roles), tenant isolation in both stores
   and both API surfaces, secret seal/open, setup commit, the pgstore
   integration tests (with `ARES_TEST_PG_URL`).
4. Open one PR on each repo; merge `ares` first, bump the server's
   `require`, then merge `ares-server`.
