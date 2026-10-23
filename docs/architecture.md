# Architecture

keel is the template for one Go binary that serves a JSON API described by a generated OpenAPI document, runs background jobs, and talks to one database. Clients (web, mobile, other services) are outside it.

Think of it as the Laravel experience for Go: everything a production app needs is set up and wired (auth, permissions, tenancy, queues, schedules, mail, files, API keys, webhooks, an artisan-style CLI), each optional part is removed at `keel init` when the app does not need it, and what remains is plain, typed, fast Go with no runtime magic.

## 1. System

```
Client ──HTTPS──> edge (optional: Cloudflare, nginx) ──> app serve ──> Postgres 18 or MySQL 9.7
  tenant hosts ─┐                                      │   (app pool; operator pool with tenancy)
  operator host ┤ realms chosen by host                │
  api host ─────┘ (bearer API keys)                    │
                                                           │
                                                           ├── jobs (table in the same database)
                                                           │     └── app worker (same binary; or inside serve)
                                                           ├── files (local disk or S3-compatible)
                                                           ├── mail (SMTP; Mailpit locally)
                                                           ├── PDF (Gotenberg, optional)
                                                           └── OTLP collector (optional)
```

No Redis and no broker. The database is the queue, the outbox, the session store and the lock service. That keeps one thing to back up and one thing to reason about. When an app outgrows it, the interfaces (`ratelimit.Store`, `jobs` handlers) are the seams to swap.

## 2. Process model

One binary, subcommands:

| Command | Does |
| --- | --- |
| `serve` | HTTP API; also runs job workers unless `APP_JOBS_IN_SERVE=false` |
| `worker` | Job workers, scheduler and reaper only (scale them apart from HTTP when needed) |
| `migrate`, `migrate:status`, `migrate:validate`, `migrate:down` | Schema changes; `down` refused in production and staging |
| `setup` | Production-safe, idempotent bootstrap: built-in roles and their permissions |
| `db:seed` | Local development data; local only |
| `user:create`, `user:grant`, `user:revoke-sessions` | People and access from the shell (first administrator, incidents) |
| `doctor`, `config:check`, `about` | What an operator checks before trusting a deploy |
| `openapi` | Print a realm's OpenAPI document (used by `make gen`) |

Optional parts and modules add their own commands; [cli.md](cli.md) lists them all.

`serve` checks the schema version at startup: it refuses to start when the database is behind the binary (migrations missing) and logs a warning when it is ahead (an older binary during a zero-downtime deploy or rollback, which expand-only migrations keep safe). Deploys are zero-downtime ([operations.md](operations.md#zero-downtime-deploys)).

## 3. Layers and dependency rules

```
cmd/app ──> internal/app ──> internal/modules/* ──> internal/kit/*
                     └──────────────────────────────> internal/kit/*
```

- `internal/kit/*` is app-agnostic. It never imports `internal/app` or any module, never names a product concept, and never reads environment variables directly (config is passed in). It may be copied between apps verbatim.
- `internal/modules/<m>` holds one product area. A module imports kit packages; its queries live only in its `store.go`, and it never queries another module's tables.
- Cross-module calls go through a small interface declared by the module that needs it, and `internal/app` wires the concrete service in. Example: `invoices` declares `type CustomerLookup interface { Customer(ctx, tx, id) (Customer, error) }`, `customers.Service` satisfies it.
- `internal/app` is the only package that knows every module. It builds `Deps`, mounts modules in order, and owns startup and shutdown.

There is no global state other than the default `slog` logger, which `logx` configures once at startup.

## 4. Module shape

```
internal/modules/notes/
  module.go       the Module the app mounts: Permissions, Register (operations), Mapper, Jobs, Commands
  permissions.go  the module's permission catalogue
  handlers.go     parse input, call the service, map results and errors to HTTP
  service.go      business rules; takes and returns domain types; no HTTP types
  rules.go        pure functions (state machines, guards, calculations) with table tests
  store.go        the module's queries, built with Jet; returns domain types
  *_test.go
internal/dbgen/   Jet table and model types for the whole schema (generated; never edited)
db/migrations/<dialect>/<timestamp>_notes_<what>.sql
```

Rules live in services, not handlers, so a job, an import, or a CLI command gets the same checks as an HTTP call. Handlers stay thin.

## 5. Request lifecycle

Order matters; each step relies on the ones before it.

0. **Realm** is chosen by host; each realm's operations are mounted on its own Huma group.
1. **chi middleware**: client address resolution (once per request; `httpx.ClientIP(ctx)` everywhere after), request id, logger context, access log, recover, body and header limits, security headers, CSRF check for unsafe methods (not on the `api` realm's hosts, which take no ambient credentials; nor CORS).
2. **Huma middleware**: pre-auth rate limit by address, session resolve for the realm (principal in context, or none), tenant resolution and membership check (tenancy), tenant access state, rate limit by the operation's class and key, `Need` enforcement (403 before the handler), restricted-session policy (MFA pending, must change password). On the `api` realm: pre-auth limit, API key resolve (401 `invalid_api_key` for a key that does not check out), limits by key and by tenant, the operation's class, `Need`, `Deprecation` and `Sunset` headers, idempotency.
3. **Handler**: validates input (Huma schema, then service rules), calls the service.
4. **Service**: opens a transaction with `db.InTx` (which sets the tenant first when tenancy is on), loads facts, calls pure rules, writes, records `audit.Record` in the same transaction, enqueues jobs in the same transaction, registers `AfterCommit` side effects.
5. **Response**: typed output struct, or problem+json with a stable `code`.

## 6. Data

- One schema per app, migrations append-only once merged (goose SQL).
- UUIDv7 primary keys made in Go; human codes are separate unique columns.
- Every table: `created_at`, `updated_at`; user-written tables add `created_by`, `updated_by`; editable rows add `version`.
- Kit tables, all created by kit migrations: `users`, `sessions`, `credentials` (password hashes), `auth_tokens`, `mfa_totp`, `mfa_recovery_codes`, `devices`, `device_pairing_codes`, `roles`, `role_permissions`, `user_roles`, `audit_log`, `audit_chain`, `jobs`, `job_schedules`, `webhook_deliveries` (inbound ids), `idempotency_keys`, `rate_counters`, `locks`, `oauth_states`, `tombstones`; with their parts `identities` (OIDC: realm, provider and subject per user), `passkeys` and `auth_challenges`, `mail_outbox`, `files`, `api_keys`, `webhook_endpoints`, `webhook_events` and `webhook_out_deliveries` (outbound webhooks), `connections`, and under tenancy `tenants`, `tenant_domains`, `memberships`, `api_key_tenants`.
- Money is integer minor units with a currency code (D18).
- Details per engine: [conventions/database.md](conventions/database.md).

## 7. Transactions and side effects

- Everything a request changes commits in one transaction: the rows, the audit entries, and the jobs it enqueues. A job is visible to workers only after commit, so the jobs table is the transactional outbox.
- Work outside the database (deleting stored objects, cache invalidation) is registered with `db.AfterCommit` and runs only after a successful commit. A commit whose outcome is unknown (`db.ErrCommitUncertain`) never runs them.
- Sending email and calling other services happens in jobs, never inside a request transaction.

## 8. Background jobs

- `queue.Enqueue(ctx, tx, kind, payload, opts...)` in the caller's transaction. Options: run at, priority, unique key (dedupe while queued or running), lane.
- Workers claim with `select ... for update skip locked`, take a lease measured on the wall clock, renew it, and cancel the handler's context when the lease can no longer be confirmed, so two workers never run one job at once for longer than one renewal interval.
- Delivery is at least once. Handlers must be idempotent; the mail outbox shows the pattern for side effects that must not repeat.
- Schedules are rows (`job_schedules`) with cron specs and a location; one enqueue per slot, under a row lock.
- A retention job prunes finished jobs, mail payloads and webhook deliveries after a configured age.

## 9. Identity, access and tenancy

- Realms (D17): `tenant`, with its own hosts, cookie, MFA policy and permission catalogue, and any an app adds.
<!-- part:tenancy -->
- The `operator` realm comes with tenancy: its own hosts, cookie, MFA policy and catalogue.
<!-- /part:tenancy -->
<!-- part:apikeys -->
- The `api` realm serves tenant API keys ([integrations.md](integrations.md)).
<!-- /part:apikeys -->
- Sign-in providers (password, OIDC, dev login, and any an app adds) all end in `Sessions.Start` (kit/auth), which rotates the session and audits in one transaction. A realm that requires MFA holds the session restricted until the second factor passes.
<!-- part:tenancy -->
- Tenancy (optional, Postgres): tenant from host or session, membership checked, tenant set per transaction, row-level security as the boundary. The operator realm alone uses the pool that crosses tenants. See [tenancy.md](tenancy.md).
<!-- /part:tenancy -->
- The principal (user, permissions, scopes) is loaded per request with a short cache, invalidated when access changes.
- Permissions are a catalogue in code; roles are data. Code checks permissions, never role names. Details: [security.md](security.md#3-authorisation).

## 10. API contract

- Huma registers operations in Go; `app openapi` prints a realm's OpenAPI 3.1 document; `make gen` writes `spec/<realm>.openapi.yaml`. Any client generates from it.
- Base path `/api/v1`. Conventions: [conventions/api.md](conventions/api.md).

## 11. Observability

- Logs: `slog`, JSON or text (`APP_LOG_FORMAT`). A context handler adds `request_id`, `user_id`, `client_ip` to every record, including records logged by kit packages.
<!-- part:otel -->
- Traces and metrics: OpenTelemetry over OTLP/HTTP, off unless `APP_OTEL_ENDPOINT` is set ([configuration.md](configuration.md#opentelemetry-optional)); without it nothing is installed or wrapped. A server span and request metrics per route pattern; a span per database query on either engine; a span per job run named after its kind, with wait and run times by kind, lane and outcome. Records logged inside a span carry its `trace_id` and `span_id`. Queue depth and age are `app doctor` and `queue:status`, not metrics.
<!-- /part:otel -->
- Health: `/livez` (process up), `/readyz` (started, database pools reachable, not draining; `serve` does not start with migrations missing). Both are rate limited; readiness checks are cached for 5 s.

## 12. Optional parts

Core parts are always present: config, logx, clock, ids, buildinfo, cli, httpx, health, server, db, migrate, testdb, auth (sessions and realms, password, tokens, TOTP, devices, dev login), users, rbac, audit, ratelimit, jobs, paging, occ, idempotency, oauthstate, seal, netguard, webhook (inbound), csvx, money, dates.

The optional parts are removed at `keel init` when not wanted, with their config, migrations and docs sections. This app keeps:
<!-- part:tenancy -->
- `tenancy` (Postgres only)
<!-- /part:tenancy -->
<!-- part:apikeys -->
- `apikeys` (and the `api` realm)
<!-- /part:apikeys -->
<!-- part:webhooks -->
- `webhooks` (outbound)
<!-- /part:webhooks -->
<!-- part:connections -->
- `connections`
<!-- /part:connections -->
<!-- part:files -->
- `files` (and S3)
<!-- /part:files -->
<!-- part:mail -->
- `mail`
<!-- /part:mail -->
<!-- part:pdf -->
- `pdf`
<!-- /part:pdf -->
<!-- part:docx -->
- `docx`
<!-- /part:docx -->
<!-- part:xlsx -->
- `xlsx`
<!-- /part:xlsx -->
<!-- part:barcode -->
- `barcode`
<!-- /part:barcode -->
<!-- part:oidc -->
- `auth/oidc`
<!-- /part:oidc -->
<!-- part:passkey -->
- `auth/passkey`
<!-- /part:passkey -->
<!-- part:otel -->
- `otel`
<!-- /part:otel -->

<!-- part:keel -->
In keel each part's wiring in `internal/app` is a pair of files: `<part>.go` (`//go:build !no<part>`) holds everything that uses the part's kit packages, and `<part>_off.go` (`//go:build no<part>`) has the same hooks as no-ops, using core types only. Core files call only the hooks; a part reaches another part only through that part's hooks, except that keel's example module (`notes`, tag `nonotes`) uses the parts it requires directly. Tests that need a part carry its constraint (`!no<a> && !no<b>` when they need two). `keel init` keeps one file of each pair and drops the constraint, so an app has no build tags. `keel check` enforces this (`part rules`: constraints, and imports of optional kit packages only from their own part's files) and vets `internal/app` and `cmd/app` with each part off, joined by the parts that require it, and with every part off. CI also lints that last build.
<!-- /part:keel -->

## 13. Performance

Fast by construction, then measured.
- Huma builds schemas and validators once at startup; Jet builds SQL from typed values; no ORM hydration.
- One round trip per query, no N+1 (children loaded with one `IN` query), keyset pagination with a bounded `limit`.
- The principal is cached for 5 s; sessions touch the database at most once a minute.
- Hot paths have benchmarks (the memory rate limiter, keyset cursors, the list envelope); `keel bench` (on demand and nightly) compares against a saved baseline (nightly: the last passing run on main) and flags a regression above 10 percent.
- Budgets an app starts from: p95 under 50 ms for a simple read and under 150 ms for a write at the database's normal latency; memory per idle instance under 64 MiB; startup under one second.
- Load testing is part of release readiness for an app (it adds a k6 or vegeta script, for example under `deploy/load/`), not of keel itself.
