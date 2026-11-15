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

## Change B: append-only audit storage

`Save` used to rewrite an engagement's whole audit trail on every change. Now it
writes only the entries added since the last save, one row per entry (Postgres
`audit_entries`, keyed `engagement_id, seq`) or one bbolt key per entry, and
rewrites the small header (status, authorization, scope, detection) only when it
changed, in one transaction. Store method signatures are unchanged; databases in
the old layout are migrated on open (after the chain verifies). Tenant
encryption seals the header and each entry separately.

| one save at a 10k-entry trail | before | after |
|---|---|---|
| Postgres | 81 ms, 26 MB allocated | 0.39 ms, 3 KB |
| Postgres footprint after 200 saves | 179 MB | 5.1 MB |
| embedded file store | 20 ms, 15 MB allocated | 0.34 ms, 15 KB |

Also fixed: on Postgres only the first 1,000 workspaces and engagements were
loaded after a restart (the generated queries' default LIMIT); loads now page.

## Change C: sessions and sign-in

- **Session and account cache.** Every request authenticates; on Postgres that
  is a round trip for the session (two once the per-request account re-check
  lands). A seconds-long in-process cache (`ARES_AUTH_CACHE_TTL`, default 2s,
  `off` to disable) serves repeats. Writes through the service evict before
  they return, so logout, disable and role changes apply on the next request;
  a read that raced an eviction is dropped, never cached; the TTL only bounds
  how long a change made by *another* server process takes to be seen.
  Authenticate on Postgres: 20 µs → 2 µs per call on loopback (the saving is
  the network round trip in production).
- **Sign-in queueing (opt-in).** PBKDF2 at 600k iterations (unchanged) costs
  ~90 ms of CPU. `ARES_KDF_CONCURRENCY=n` caps derivations in flight so a
  sign-in burst queues instead of occupying every core. It is off by default:
  on 2 cores, a cap of 1 doubled the time to sign 1,000 users in (47 s → 94 s)
  and did not improve read latency during a 400-sign-in burst (p99 680 ms
  uncapped vs 772 ms capped, both with 1,000 users reading). Worth setting on
  larger hosts that must stay responsive through mass sign-ins.
- **Expired sessions are swept** every 15 minutes (they were only deleted when
  presented again, so abandoned ones accumulated forever); Postgres sessions
  are indexed on `user_id` and `expires_at`.

| 1,000 users reading + 400 sign-ins at once | uncapped | `ARES_KDF_CONCURRENCY=1` |
|---|---|---|
| throughput | 2,426 req/s | 2,295 req/s |
| p50 / p95 / p99 | 224 / 468 / 680 ms | 255 / 502 / 772 ms |
| peak RSS | 390 MB | 403 MB |

## Change D: job outcomes on disk, bounded memory

- **Persisted, compressed job outcomes.** Results used to live only in memory,
  unbounded, and vanished on restart along with every finding. Finished
  outcomes are now stored once as zstd-compressed JSON (Postgres
  `job_outcomes`, or a bbolt bucket), with running jobs kept in memory until
  they finish. An LRU keeps recently used engagements' outcomes decoded,
  bounded by total results (`ARES_OUTCOME_CACHE_RESULTS`, default 200k);
  others are read back on use, and the memoized views above mean that is one
  read per change, not per request. Finding triage statuses are rebuilt from
  the audit trail on start, so they survive too.
- **Soft memory limit.** Without `GOMEMLIMIT`, the server sets one at 90% of
  the container's cgroup limit, so the GC tightens before an OOM kill.
- **Idle connections** close after 2 minutes; header size is capped at 64 KiB.
- **Full queue fails fast.** A dispatch to a full job queue returns
  `ResourceExhausted` (REST: 503 + `Retry-After`) instead of blocking the
  request until a worker frees a slot.

Outcomes and finding statuses were checked end to end: 51 findings and their
triage statuses (including one changed just before) came back identical after a
server restart; before this change a restart left zero findings.

### More users (all changes, same 2+2 core split)

| users | throughput | p50 / p95 / p99 | server CPU | peak RSS |
|---|---|---|---|---|
| 1,000 | 2,532 req/s | 178 / 295 / 387 ms | 1.35 cores | 147 MB |
| 2,000 | 2,059 req/s | 660 ms / 1.17 s / 1.67 s | 1.42 cores | 392 MB |
| 4,000 | 1,999 req/s | 1.54 / 2.95 / 4.09 s | 1.45 cores | 510 MB |
| 4,000, `ARES_COMPRESSION=off` | 2,246 req/s | 1.36 / 2.25 / 2.88 s | 1.08 cores | 388 MB |

Past 1,000 users the server used only 1.1 to 1.45 of its 2 cores while latency
grew, so the limit in these runs is outside the server's CPU, most likely the
load generator sharing the same 4-core box (it holds thousands of connections
and decodes every response on 2 cores). Treat the 2,000+ rows as a floor; a
fair ceiling needs the load generated from a separate machine. Every sign-in
succeeded and no request failed at 4,000 users, and memory stayed near 0.1 MB
per signed-in user.
