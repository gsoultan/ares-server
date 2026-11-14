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
cmd/ares-devseed       seeds a local dev install with demo content
cmd/ares-practice      deliberately weak, loopback-only practice target
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
scripts/               dev, codegen, setup and Postgres scripts
samples/               synthetic demo inputs for the seeded dev run
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

One command runs everything you need to work on Ares and to show it:

```sh
scripts/setup.sh          # one-time: proto toolchain + web deps, then generate
scripts/dev.sh            # run the seeded demo; Ctrl-C stops everything it started
```

`scripts/dev.sh` builds and starts, together:

- the **control plane** on `:8080`,
- the **web UI** at <http://127.0.0.1:5173> (its dev server proxies control-plane
  calls to the backend, so the browser stays same-origin),
- the **practice target** (`cmd/ares-practice`) at <http://127.0.0.1:8089>: a
  small, deliberately weak site that listens on loopback only. Its weaknesses
  are simulated (canned fake files, arithmetic-only "templates", a fixed fake
  passwd line) so the checks have something safe to find,
- on a Mac with Apple's [`container`](https://github.com/apple/container) CLI,
  **PostgreSQL** in a container on its own port (see below).

It has two modes:

| Command                  | What you get                                                          |
| ------------------------ | --------------------------------------------------------------------- |
| `scripts/dev.sh`         | **Seeded demo.** Skips the `/setup` wizard. Sign in as `admin@northwind.db` / `admin`. Workspace "Northwind Traders" (plus an empty "Contoso" one), engagement "Northwind practice lab" authorized for `127.0.0.1` only, and findings from safe checks against the practice target and from forensic jobs over `samples/`. Data persists in `.dev/`. |
| `scripts/dev.sh --fresh` | The same, after wiping `.dev/` and reseeding.                         |
| `scripts/dev.sh --setup` | **First run.** In-memory and empty, so the app opens on the `/setup` wizard. Nothing is kept. |

Add `--no-pg` to either to skip the PostgreSQL container. Job results and finding
statuses are held in memory by the server today, so the seeded demo re-runs its
sample jobs on every start; accounts, workspaces and engagements persist.

> **The demo credential is for local development only.** `admin` is shorter than
> the 12-character policy; only the dev seeder (`cmd/ares-devseed`) can write it,
> through `auth.HashPasswordForDevSeed`. The setup wizard, the API and the UI
> still enforce the policy. Never point the seeder or `scripts/dev.sh` at a real
> deployment.

Optional environment variables:

| Variable        | Default              | Meaning                                         |
| --------------- | -------------------- | ----------------------------------------------- |
| `ARES_ADDR`     | `:8080`              | control-plane listen address                    |
| `WEB_PORT`      | `5173`               | web dev-server port                             |
| `PRACTICE_ADDR` | `127.0.0.1:8089`     | practice target (must be a loopback address)    |
| `DEV_DIR`       | `.dev`               | seeded database and master key                  |
| `DEV_EMAIL`     | `admin@northwind.db` | demo super-admin email                          |
| `DEV_PASSWORD`  | `admin`              | demo super-admin password                       |
| `ARES_PG`       | `auto`               | `on`, `off`, or `auto` (on when `container` is installed) |
| `ARES_PG_PORT`  | `55433`              | PostgreSQL host port                            |

#### PostgreSQL in an Apple container

`scripts/postgres.sh` runs PostgreSQL 17 in Apple's `container` runtime (macOS 26
on Apple silicon), published on `127.0.0.1:55433` rather than the default 5432,
in a container named `ares-dev-postgres` with its own volume, so it does not
clash with other Postgres instances or containers on the machine.
`scripts/dev.sh` starts it and leaves it running when you stop the stack.

```sh
scripts/postgres.sh up | down | status | psql | url | destroy
```

The dev script exports the container's URL as `ARES_PG_URL`, but it also sets
`ARES_DB` to the seeded file store, and `ARES_DB` wins, so the demo runs on the
embedded file store. To run the server on the storm-based Postgres datastore,
set `ARES_DB` (or only `ARES_PG_URL`) to a `postgres://` URL.

#### Sample files

`samples/` holds the demo inputs: web-server and SSH logs, a threat-indicator
list, a WordPress site backup with planted (inert) backdoors, a synthetic
Android app, and the demo authorization letter. Upload them on the Forensics
page to try those flows by hand. See `samples/README.md`.

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

