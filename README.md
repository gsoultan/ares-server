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

Scaffold only. The move plan and the reasoning behind the library boundary are
in [`docs/split-plan.md`](docs/split-plan.md). The code moves here from `ares`
once its storm-based Postgres datastore (ares PR #7) is merged.

## Planned layout

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
