# Performance and footprint

Goal: thousands of concurrent operators on a small box, with low CPU, memory
and disk. This page records what was measured, what was changed, and how to
reproduce the numbers.

## How to measure

```sh
# Micro-benchmarks (the pgstore ones need a throwaway Postgres)
go test ./internal/... -run x -bench . -benchtime 20x
ARES_TEST_PG_URL=postgres://ares@127.0.0.1:55433/ares?sslmode=disable \
  go test ./internal/store/pgstore -run x -bench . -benchtime 200x

# End-to-end: seed a dev install, then drive it with N signed-in users
ARES_PPROF_ADDR=127.0.0.1:6060 ares-server &          # pprof on loopback only
ares-devseed populate                                  # repeat to add jobs
ares-loadtest -email admin@northwind.db -password admin \
  -users 1000 -duration 30s -think 1s -pid $(pgrep ares-server)
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=20
```

`ares-loadtest` gives every virtual user its own session and loops over the
reads the web UI makes while someone works an engagement (engagement list and
detail, jobs, one job, findings, risk card, audit trail, current user), with an
exponential think time and 2% writes (finding status). It never dispatches a
job, so it touches no target.

Numbers below: 4-core Xeon 2.3 GHz, embedded store, server pinned to 2 cores
and the load generator to the other 2 (`taskset`), 1,000 users, 1 s think time,
the dev seed populated 5 times.

## Findings (baseline)

| # | Where | Measured |
|---|---|---|
| 1 | Findings / job / risk views rebuild everything per request; each finding's data goes map → JSON → protobuf | `mapToStruct` + `protojson` ≈ 31% of steady-state CPU; ListFindings 7.0 ms per call for a 10-engagement workspace |
| 2 | Responses gzipped at the default level, however small | ≈ 31% of steady-state CPU |
| 3 | `ByEngagement` scans every outcome on the server and re-sorts | GetRiskPicture 0.49 ms with 10k unrelated outcomes |
| 4 | Live job progress copies every result so far on each new result | one 5,000-result job: 552 ms, **1.5 GB** allocated |
| 5 | Engagement `Save` rewrites the whole audit trail | at 10k entries: Postgres 86 ms / 28 MB per save, and 200 saves left a 179 MB table (dead TOAST); storm 20 ms / 15 MB |
| 6 | Sign-in is PBKDF2-SHA256 at 600k iterations | 91 ms CPU each; 1,000 sign-ins pinned every core for 24–47 s |
| 7 | Every request loads the session from the database | 43 µs on local Postgres, plus a network round trip in production |
| 8 | Job outcomes live only in memory | unbounded growth, lost on restart |

## Change A: fast read path

- Direct `map[string]any` → `structpb` conversion, falling back to the JSON
  round trip for anything that is not plain JSON-shaped (a test pins both paths
  to identical output). 1.3 µs vs 9.0 µs per payload, 30 vs 109 allocations.
- Per-engagement outcome index and version counter in the outcome store, so an
  engagement's views cost O(its own jobs).
- A small memo for derived views (findings, risk picture, job outcome, audit
  trail). Each entry is keyed by the caller's workspace and carries a
  fingerprint of the versioned inputs it was built from, so it is reused only
  while those inputs are unchanged; nothing is ever served stale.
- O(1) progress snapshots (capped slices share the append-only backing array).
- Fastest gzip level and no compression under 1 KiB. `ARES_COMPRESSION=off`
  turns response compression off (best when clients are on the LAN or a TLS
  proxy compresses), `default` restores gzip's default level.
- `ARES_PPROF_ADDR` serves pprof on its own listener (keep it on loopback).

| | before | after (fast gzip) | after (`ARES_COMPRESSION=off`) |
|---|---|---|---|
| throughput | 1,444 req/s | 2,716 req/s | 4,074 req/s |
| p50 / p95 / p99 | 226 ms / 1.02 s / 6.95 s | 149 ms / 256 ms / 340 ms | 67 ms / 128 ms / 190 ms |
| server CPU | 1.73 cores | 1.32 cores | 1.24 cores |
| CPU per request | 1.20 ms | 0.49 ms | 0.30 ms |
| peak RSS | 250 MB | 124 MB | 115 MB |

Micro-benchmarks: ListFindings (warm) 7.0 ms → 0.18 ms; GetRiskPicture 0.49 ms
→ 6 µs; 5,000-result job 552 ms / 1.5 GB → 13 ms / 9.9 MB.

## Next

- **B. Append-only audit storage.** `Save` writes a small header (status,
  authorization, scope, detection) only when it changed, and appends only the
  new audit entries as their own rows keyed (engagement, seq). Store method
  signatures stay the same; tenant encryption seals the header and each entry
  separately.
- **C. Session cache and sign-in queueing.** A seconds-long in-process cache of
  session + user with explicit invalidation on logout, disable and role change;
  a cap on concurrent PBKDF2 work so a sign-in burst queues instead of starving
  every other request (iterations stay at 600k).
- **D. Bounded, persisted job outcomes; `GOMEMLIMIT`; server timeouts; a
  2,000–5,000 user run.**
