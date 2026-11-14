# Ares Server

The server side of Ares, the self-hosted platform for **authorized** security
testing. Ares is split into two repositories:

| Repository | Owns |
|---|---|
| [`gsoultan/ares`](https://github.com/gsoultan/ares) — the **engine** | recon and fingerprinting, the check and attack modules, the scenario catalog, the permission gate, the HTTP client and rate governor, forensics (APK / IPA scan, WordPress, archives) |
| `gsoultan/ares-server` — the **server** (this repo) | workspaces (multi-tenancy), accounts, sessions and roles, sealed secrets, the settings store, first-run `/setup`, the datastore (embedded file store and storm-based Postgres), engagements and the audit trail, job queue and workers, reports, the REST and gRPC control plane, and the web UI |

The server imports the engine as a Go library and only uses its public
packages (`engine`, `module`, `scope`, `canary`, `intel`, `detection`,
`purple`, `remediation`). Nothing touches a target without passing the
engine's permission gate.

> **Authorized use only.** Ares tests systems you own or have explicit,
> written permission to test.

## Status

The server code moved here from `ares` (with the storm-based Postgres
datastore). Why the server uses the engine as a library rather than a separate
service, and exactly what moved, is in [`docs/split-plan.md`](docs/split-plan.md).

## Layout

```
cmd/ares-server        the server binary (control plane + worker pool)
internal/auth          accounts, PBKDF2 passwords, roles, sessions
internal/tenant        workspaces, the isolation boundary
internal/secret        AES-256-GCM sealed secrets
internal/settings      per-workspace settings (AI advisory, OSINT keys)
internal/setup         first-run setup wizard
internal/engagement    engagements, authorization, lifecycle
internal/audit         hash-chained, tamper-evident log
internal/store/        stormstore (embedded) and pgstore (Postgres via storm)
internal/queue         job queue
internal/worker        runs engine modules behind the permission gate
internal/report        PDF / DOCX / Markdown reports
internal/ai            AI advisory providers
internal/api           REST control plane
internal/connectapi    gRPC (Connect) control plane
internal/gen           generated protobuf / Connect code
proto/                 the control-plane contract
web/                   operator web UI (PWA)
scripts/               dev, codegen and setup scripts
```

## Develop

Both repositories are private, so tell Go not to use the public proxy for
them:

```sh
go env -w GOPRIVATE=github.com/gsoultan/*
```

To work on the engine and the server together, use a workspace:

```sh
go work init . ../ares
```

Go 1.27.3 or newer is required.

## Client workspaces (multi-tenancy)

A security team runs engagements for many clients, and one client's engagements,
scope, findings and audit trail must never be visible from another's. Ares groups
engagements into **workspaces** (tenants): every engagement belongs to exactly
one, listing is scoped to a single workspace, and reading or acting on an
engagement from another workspace returns *not found* — an id leaks nothing
across the boundary. Isolation is enforced in the store and at both API surfaces,
not left to convention (`internal/tenant`).

A built-in **default workspace** always exists, so a single-client deployment
needs no setup and databases written before workspaces existed keep working:
their engagements load into the default workspace. Over REST the workspace is
the `X-Ares-Tenant` header (absent means the default); over gRPC it is the
`tenant_id` field on each request. The web UI has a workspace switcher in the
header and sends the selection on every call.

## Persistence

Workspaces, engagements, their scope, authorization and the audit trail are
stored in an embedded [Storm](https://github.com/asdine/storm) database (a
single bbolt file), so the control plane survives a restart. The store keeps the
live engagements in memory and writes each change through to disk; on startup it
reloads every workspace and engagement and **verifies each audit chain at rest**,
refusing to start if one has been altered outside the application. Set `ARES_DB` to choose
the file (default `ares.db`), or `ARES_DB=memory` for an ephemeral run.

## Interfaces

The control plane is served two ways over one core, so the permission gate and
the audit trail are identical whichever a client uses:

- **gRPC** (the primary interface): the `ares.v1.ControlPlane` service, defined
  in `proto/ares/v1/ares.proto` and served by connect-go. It speaks gRPC,
  gRPC-Web and the Connect protocol on the same endpoint, over HTTP/2 (plaintext
  h2c in step 1, ordinary gRPC behind TLS). The contract is compiled with
  [buf](https://buf.build) (`buf generate`).
- **REST/JSON**: the `/api/...` routes below, for quick manual use with `curl`.

## Run it

```sh
go test ./...                 # all green
go run ./cmd/ares-server         # listens on :8080 (ARES_ADDR to change)
```

### Local development (the whole stack)

Convenience scripts in `scripts/` boot the Go control plane and the web UI
together:

```sh
scripts/setup.sh   # one-time: install the proto toolchain + web deps, then generate
scripts/dev.sh     # run the control plane and the web UI together; Ctrl-C stops both
scripts/gen.sh     # regenerate the gRPC/Connect bindings after editing the .proto
```

`scripts/dev.sh` serves the app at <http://127.0.0.1:5173> (the web dev server
proxies control-plane calls to the backend on `:8080`). It reads a few optional
environment variables:

| Variable    | Default    | Meaning                                              |
| ----------- | ---------- | ---------------------------------------------------- |
| `ARES_ADDR` | `:8080`    | control-plane listen address                         |
| `ARES_DB`   | `memory`   | database path, or `memory` for an ephemeral dev run  |
| `WEB_PORT`  | `5173`     | web dev-server port                                  |

The dev runner defaults to an in-memory database so each run starts clean; set
`ARES_DB=ares.db` to keep state between runs.

### A walk-through

```sh
BASE=http://127.0.0.1:8080

# 1. Create an engagement
EID=$(curl -s -X POST $BASE/api/engagements -d '{"name":"Demo"}' | jq -r .id)

# 2. Define what may be tested, and what is off-limits
curl -s -X POST $BASE/api/engagements/$EID/scope \
  -d '{"inScope":["example.com"],"exclude":["secret.example.com"]}'

# 3. Attach signed permission (jobs are refused until this is done)
curl -s -X POST $BASE/api/engagements/$EID/authorize \
  -d '{"document":"authorization-letter.pdf","approvedBy":"Engagement lead"}'

# 4. Dispatch a job; out-of-scope and excluded targets are dropped and logged
JID=$(curl -s -X POST $BASE/api/engagements/$EID/jobs \
  -d '{"module":"httpprobe","targets":[{"url":"https://www.example.com/"}]}' | jq -r .jobId)

# 5. Read the outcome and the audit trail
curl -s $BASE/api/jobs/$JID
curl -s $BASE/api/engagements/$EID/audit
```

## API

All engagement routes act within a workspace: send `X-Ares-Tenant: <id>` to pick
one, or omit it for the default workspace.

| Method & path | Purpose |
|---|---|
| `GET /healthz` | liveness |
| `GET /api/modules` | list registered capabilities |
| `POST /api/tenants` | create a client workspace |
| `GET /api/tenants` | list workspaces |
| `POST /api/engagements` | create an engagement (in the request's workspace) |
| `GET /api/engagements` | list the workspace's engagements |
| `GET /api/engagements/{id}` | engagement detail |
| `POST /api/engagements/{id}/scope` | set in-scope, exclusions and window (draft only) |
| `POST /api/engagements/{id}/authorize` | attach signed permission; enables running |
| `POST /api/engagements/{id}/halt` | kill switch: stop running anything more |
| `POST /api/engagements/{id}/jobs` | dispatch a module against targets (refused if not authorized) |
| `GET /api/jobs/{jobId}` | job outcome (allowed, denied, results) |
| `GET /api/engagements/{id}/audit` | the hash-chained audit trail and its validity |
| `GET /api/engagements/{id}/report?format=pdf\|docx\|md` | download a client-ready report |

## Reports

Any engagement can be exported as a client-ready report in **PDF**, **DOCX** or
**Markdown** (`GET /api/engagements/{id}/report?format=…`, or the
`GenerateReport` RPC; the web UI has download buttons on the engagement page).
A report gathers the engagement header and authorization, the approved scope,
the findings from every job it ran (most serious first, each with what was
found, what it means and how to fix it), and the state of the tamper-evident
audit trail. The PDF and DOCX writers are built from the standard library
alone — no external toolchain or service — so reporting keeps Ares a single
static binary.

