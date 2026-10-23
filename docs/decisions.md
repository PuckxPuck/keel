# Decisions

Short records. Each says what was decided, why, and what would change it. Add new ones at the end; never rewrite an old one, supersede it.

## D1. Copy-per-project template (2026-10-22)
Decided: keel is copied into each new app by `make init`; the app owns the copy.
Why: apps diverge, and a shared library would force every app to move in step. A template keeps each app free and self-contained.
Cost: fixes do not flow automatically. Mitigated by keeping `internal/kit` app-agnostic and never edited per app, so upgrades are diffs ([operations.md](operations.md#upgrading-kit-code)).
Revisit if: three or more apps carry identical kit code and upgrades start lagging. Then extract `internal/kit` into a versioned module.

## D2. Modular monolith (2026-10-22)
Decided: `internal/kit`, `internal/modules/<m>`, `internal/app`; modules talk through interfaces declared by the consumer.
Why: one deploy, one transaction boundary, clear seams if a module ever needs to leave.
Revisit if: a module needs its own scaling or release cadence.

## D3. chi + Huma (2026-10-22)
Decided: chi v5 for routing and standard middleware, Huma v2 for operations, validation, OpenAPI 3.1 and problem+json.
Why: code-first contract means no hand-maintained YAML that drifts; parallel work does not collide on one spec file; any client generates from the output.
Revisit if: Huma stalls. The handler and service split keeps a move contained to `handlers.go` and `module.go`.

## D4. database/sql for both engines, sqlc, goose (2026-10-22; query layer superseded by D23)
Decided: `database/sql` with pgx's stdlib driver (Postgres) or go-sql-driver/mysql (MySQL). sqlc generates typed queries per dialect; goose runs SQL migrations.
Why: one transaction type (`*sql.Tx`) through every kit and module function, whichever engine the app chose. Kit code is written once.
Cost: no pgx-native batch, COPY or richer types through the generated code. Still reachable through `conn.Raw` when an app needs them.
Exit plan: if the P2 spike shows sqlc on `database/sql` cannot handle Postgres arrays and uuid overrides cleanly, Postgres apps use pgx native (`pgx.Tx`) and the kit defines a `db.Tx` interface with the few methods it needs. Decided after the spike, recorded as a new entry.

## D5. Database chosen at init (2026-10-22)
Decided: kit SQL, migrations and stores exist for Postgres and MySQL and are tested on both. `make init DB=postgres|mysql` keeps one. App modules are written in that one dialect only.
Why: supporting both at runtime would double every module's queries and tests forever, for a choice that is made once.
Revisit if: an app must run on both engines at once (unlikely; then it needs a store interface per module).

## D6. UUIDv7 ids, char(36) on MySQL (2026-10-22)
Decided: ids are UUIDv7 made in Go. Postgres stores `uuid`; MySQL stores `char(36) character set ascii collate ascii_bin`.
Why: the same Go value (`uuid.UUID`, which scans and writes as text) works on both engines with no custom types; v7 is time-ordered so inserts stay near the end of the index. Generating ids in Go removes the need for `RETURNING`, which MySQL lacks.
Cost: 36 bytes instead of 16 per key on MySQL. Irrelevant below tens of millions of rows.
Revisit if: a MySQL table grows past that; switch that table to `binary(16)` with a typed column.

## D7. Named locks through a table (2026-10-22)
Decided: `db.Lock(ctx, tx, name)` upserts a row in `locks` and selects it `for update`. The lock lasts until the transaction ends.
Why: Postgres advisory locks and MySQL `GET_LOCK` behave differently (transaction vs session scope). A row lock behaves the same on both and shows up in normal lock monitoring. Names are readable strings, not magic numbers.
Cost: one small table with a row per lock name.

## D8. Opaque server-side sessions (2026-10-22)
Decided: random token in a cookie (browsers) or `Authorization: Bearer` (other clients), SHA-256 stored, idle and absolute expiry, rotation on sign-in.
Why: instant revocation, nothing to leak from the database, no key management for signing. JWTs suit third-party token exchange, not first-party sessions.

## D9. Pluggable identity providers (2026-10-22)
Decided: password, OIDC and dev login ship, with TOTP and passkeys as second factors (D21); an app adds its own (for example an organisation's SSO with a provisioning webhook) as a provider plus a module, without touching kit code. Every provider ends in `auth.StartSession`.
Why: ported apps arrive with password users (often bcrypt); new apps often use an SSO. Both need the same session, audit and rate-limit path.

## D10. Permission catalogue in code, roles as data, enforced Need (2026-10-22)
Decided: as in [security.md](security.md#3-authorisation). `Need` metadata is enforced by middleware, not just documented.
Why: a declared-but-unenforced permission is worse than none: it reads as protected. Enforcing it centrally and checking contextual rules in services gives two layers.

## D11. Jobs in the database (2026-10-22)
Decided: in-house `jobs` package on a table in the app's database.
Why: works on both engines (`for update skip locked` exists on Postgres and MySQL 8), enqueue joins the caller's transaction, no extra infrastructure. River would be a strong choice on Postgres only, which D5 rules out.
Revisit if: throughput needs exceed a few hundred jobs a second sustained.

## D12. Optional parts removed at init (2026-10-22)
Decided: files, S3, mail, PDF, docx, OIDC, OpenTelemetry can be dropped at init.
Why: an app that does not send mail should not carry mail config, tables and tests. Removal at init keeps the result honest; runtime flags would leave dead code.

## D13. Tools in go.mod (2026-10-22)
Decided: golangci-lint, govulncheck, goose, the Jet generator and oasdiff are `tool` directives in a separate `tools/go.mod`, run with `go tool -modfile=tools/go.mod <name>` (wrapped by `keel` and the Makefile).
Why: one pinned version for every developer and CI, no install scripts piped from the network, and the tools' large dependency graphs never touch the app's own `go.mod` (golangci-lint advises against sharing one).

## D14. Logs always, OpenTelemetry when configured (2026-10-22)
Decided: JSON `slog` everywhere; OTel traces and metrics only when an OTLP endpoint is set.
Why: small deployments do not run a collector; larger ones get traces without code changes.

## D15. Single Go module at the repository root (2026-10-22)
Decided: `go.mod` at the root. An app that adds a web client puts it in `web/` (or a separate repo).
Why: backend-only template; root module keeps paths short for services, workers and CLIs.
Note: if a JavaScript client lives in `web/` and `node_modules` ever contains `.go` files, add a `web/go.mod` stub so `./...` skips it.

## D16. Optional tenancy on Postgres row-level security (2026-10-22)
Decided: an optional `tenancy` part. Shared tables, `tenant_id` on every tenant row, Postgres row-level security as the boundary, the tenant set per transaction with `set_config(..., true)`. Postgres only; `make init` refuses tenancy with MySQL. Design in [tenancy.md](tenancy.md).
Why: application-level scoping (global scopes, `where tenant_id = ?` in every query) fails open the first time someone forgets it. RLS fails closed: a query with no tenant set returns nothing. MySQL has no row-level security, and keel would rather not offer a weaker tenancy under the same name.
Cost: three database roles, a policy per tenant table, `tenant_id` in composite keys, and no `COPY FROM` into tenant tables.
Revisit if: an app needs tenancy on MySQL; that would be an app-level design with its own name and tests, not this part.

## D17. Session realms (2026-10-22)
Decided: `auth` sessions belong to a realm. A realm has its own hosts, cookie, expiry, MFA policy, principal loader and permission catalogue. A typical SaaS app has two: `tenant` (customers' users) and `operator` (the people who run the service). A session never crosses realms.
Why: operators need cross-tenant access, mandatory MFA and a separate cookie on a separate host. One binary with two realms shares domain code and deploys; the operator realm alone gets the operator database pool.
Alternative: the operator side as a separate app. Choose that when it shares little domain code with the tenant side.

## D18. Money in integer minor units (2026-10-22)
Decided: amounts are `int64` minor units with an ISO 4217 code (`bigint` plus `char(3)` in the database; `{"amount": 1250, "currency": "USD"}` in JSON). The exponent comes from the currency (2 for most, 3 for KWD and BHD, 0 for JPY). Decimals (`shopspring/decimal`) only for rates, tax percentages, fractional quantities and FX, and every conversion back to money rounds once with a named mode.
Why: integers sum exactly, sort and index cheaply, and survive JSON and JavaScript without precision loss (up to 2^53). Offline clients and receipts handle them without a decimal library.
Supersedes: the earlier `numeric(19,4)` and string-decimal convention.

## D19. Kit directory is internal/kit (2026-10-22)
Decided: app-agnostic packages live in `internal/kit`, not `internal/platform`.
Why: "platform" is what many SaaS products call their operator side. Two meanings of one word in one codebase makes every conversation ambiguous.

## D20. argon2id parameters from configuration (2026-10-22)
Decided: parameters are config; the default is OWASP's m=19 MiB, t=2, p=1. Apps on larger hosts can raise them; `NeedsRehash` upgrades hashes on the next sign-in.
Why: many staff signing in at once (a shift change) at 64 MiB each exhausts a small host. The concurrency semaphore still applies.
Supersedes: the RFC 9106 second option (m=64 MiB, t=3, p=4) as the default; it remains a documented profile.

## D21. Second factors (2026-10-22)
Decided: TOTP with recovery codes is part of core `auth` (off per realm until enabled); passkeys are an optional part because go-webauthn is pre-1.0. A realm's MFA policy is `off`, `optional` or `required`.
Why: an operator realm should require MFA from day one; tenant users usually get it as an option.

## D22. Currency check of the stack (2026-10-22)
Checked every choice against what is current, not only library versions:
- Database targets moved to Postgres 18 (17 still supported, 19 joins CI at GA) and MySQL 9.7 LTS (8.4 LTS still supported).
- S3 client is the AWS SDK v2 instead of minio-go, and SeaweedFS replaces MinIO in local tests: the MinIO community project is in maintenance mode and no longer publishes images.
- Password length follows NIST SP 800-63B-4: 15 minimum as a single factor, 8 with a required second factor.
Known compromises that are deliberate, not oversights:
- `database/sql` on Postgres (D4) gives up pgx-native performance and types so kit code serves both engines. Postgres-only apps are the likely majority, so the P2 spike also measures the cost; if it is material, Postgres apps move to pgx native.
- In-house jobs (D11) instead of River, which is the stronger choice on Postgres but Postgres-only.
- `char(36)` ids on MySQL (D6) instead of `binary(16)`.
- OpenAPI 3.1, not 3.2: Huma emits 3.1 and most client generators do not support 3.2 yet.

## D23. Jet instead of sqlc; tenant never written in queries (2026-10-22)
Decided: queries are built with Jet (`github.com/go-jet/jet/v2`), whose table and model types are generated from the migrated schema. sqlc is dropped. Tenant scoping is never written in application queries: row-level security filters, and a `tenant_id` column default fills inserts.
Why: Rafhaan wants ORM-like ergonomics over hand-written SQL files. Jet gives typed, compile-checked queries built in Go, so dynamic filters, sorts and keyset paging are ordinary code (sqlc needed one query per sort). It has no ORM runtime (no reflection-driven loading, hidden queries or hooks), supports Postgres and MySQL, runs on `database/sql` (fits D4), and is a stable v2.
Tenant injection by an ORM scope (Laravel global scopes, GORM scopes) was considered and rejected: it fails open whenever a raw query, a join, or a deliberate bypass skips the scope. Database-enforced scoping fails closed and needs no code at all.
Alternatives: GORM (reflection, runtime errors, scopes fail open), ent (pre-1.0, schema in Go, heavy generated code), Bun (runtime-checked), Bob (closest fit with relation loading and factories, but pre-1.0 with an API that still moves; revisit at its 1.0).
Cost: generation needs a migrated database (`make gen` makes a scratch one); kit stores still exist per dialect because Jet has a package per dialect.

## D24. One response envelope, not JSON:API (2026-10-22)
Decided: success responses are `{data, meta?, links?}` built from generic Go types (`httpx.One[T]`, `httpx.List[T]`, `httpx.Feed[T]`); every error is RFC 9457 problem+json. A walk test fails on any operation whose output is not an envelope.
Why: Rafhaan's requirement is that no response ever comes back in a different format. Enforcing it in the type system guarantees that. JSON:API (v1.1) was considered: it is a real standard, but it nests fields under `data.attributes`, puts related records in an untyped `included` array that generated clients type poorly, has its own error format competing with RFC 9457, and Huma does not support it. The major public APIs (Stripe, GitHub) use plain resources with a consistent top level, as here.
Revisit if: a consumer requires JSON:API specifically; a JSON:API rendering of the `api` realm could be added as an adapter over the same types.

## D25. Tenant API keys and a public api realm (2026-10-22)
Decided: optional `apikeys` part. Keys belong to a tenant, carry scopes drawn from permissions marked API-grantable, use a secret-scanner-friendly format with a checksum, are stored as SHA-256, and authenticate on a third realm, `api`, which exposes only operations marked `apikeys.Public`. That realm has its own OpenAPI document and a strict no-breaking-changes check. Details in [integrations.md](integrations.md).
Why: plugins and accounting connectors need stable, tenant-scoped, revocable machine access that survives staff changes. Keys are simplest for the app's own plugins; an OAuth 2.1 authorization server is added when third-party developers build apps.

## D26. Outbound webhooks and connections (2026-10-22)
Decided: optional `webhooks` (tenant endpoints, events emitted in the causing transaction, Standard Webhooks signing, SSRF-safe delivery) and `connections` (encrypted per-tenant OAuth tokens for calling other services, with locked refresh).
Why: integrations are two-way. Emitting inside the transaction means a rolled-back change never notifies anyone; locking refresh avoids losing rotating refresh tokens.

## D27. Command line: ops in the binary, generators in a dev tool (2026-10-22)
Decided: `kit/cli` (stdlib `flag`, about 200 lines) gives artisan-style `group:action` commands. The production binary `app` carries runtime and operator commands, including `doctor`; the dev tool `keel` carries generators and checks and is never built into a release. Commands list in [cli.md](cli.md).
Why: one familiar way to run and inspect everything, without shipping scaffolding code to production. A CLI framework (cobra, urfave/cli) adds weight for features keel does not need.

## D28. Type safety, memory safety and speed rules (2026-10-22)
Decided: rules in [conventions/go.md](conventions/go.md#type-and-memory-safety) and [architecture.md](architecture.md#13-performance): typed ids per entity, typed enums with exhaustive switches, no `any` in domain code, no `unsafe` or cgo (`CGO_ENABLED=0`, depguard), `-race` on every test run, fuzz tests on every parser of outside input, nilaway as an advisory check, reflection only at startup. Performance is a budget with benchmarks in CI, not a slogan.
Why: Go is memory safe except through `unsafe`, cgo and data races; closing those three keeps it so. Typed ids stop the most common real bug in this kind of code (passing an order id where a customer id belongs), and the compiler catches it.

## D29. Tenant and operator transactions are different types (2026-10-22)
Decided: `db.InTx` hands out `db.Tx[db.Tenant]` on the app pool (tenant set) and `db.Tx[db.Operator]` on the operator pool. Tenant stores accept only `Tx[Tenant]`; operator stores only `Tx[Operator]`. `Tx[Operator]` can be opened only through a capability given to operator-realm modules when `internal/app` wires them, so every module that crosses tenants is visible in one place. Both expose `.Q()` (a Jet `qrm.Queryable`) for queries.
Amended in the P2 fix pass: each `Tx[S]` carries a zero-size `[0]S` field, so no conversion turns one scope into another (a test checks every pair). `.Q()` returns a wrapper with only query and exec, never the `*sql.Tx`, so only `InTx` commits. `db.Open` is the only place the operator capability is made (`*OperatorAccess`, nil without an operator URL); `internal/app` keeps it. Lint (forbidigo) allows `DB.SQL()` only in `internal/kit`, `cmd` and tests (never `internal/app` or modules), and `db.OnBegin`/`db.BeforeCommit` only in `internal/kit/tenancy` (and tests), which closes the routes around the types: a no-op tenant begin hook or the raw pool.
Why: passing the wrong transaction becomes a compile error instead of a review comment. Learned from PlatformKit (see [research/2026-10-22-platformkit.md](research/2026-10-22-platformkit.md)).

## D30. Nobody but kit/db writes the tenant setting (2026-10-22)
Decided: `app.tenant_id` is a custom setting, and Postgres lets any role change a custom setting, so row-level security alone cannot stop code that rewrites it mid-transaction. Two controls: a check in `keel check` that fails when anything outside `kit/db` mentions `app.tenant_id`, `set_config`, `SET LOCAL` or `SET ... app.` (Go and SQL, migrations included); and `db.InTx` re-reads the setting before commit and rolls back if it changed. Cross-tenant access never uses a setting at all: it is a different database role (D16), which code cannot switch to.
Why: closes the one way around row-level security that a role-based design leaves open.

## D31. Security counters live in the database (2026-10-22)
Decided: limits that protect secrets (sign-in failures, MFA attempts, reset and verification requests, code redemption, API key failures) use `ratelimit.DBStore`: a fixed-window row per key, updated with one upsert, on the operator pool in its own short transaction so a failed request's rollback does not erase its own count. General traffic limits stay in memory (token buckets) because a few extra requests across replicas are harmless there.
Why: with several replicas an in-memory lockout multiplies the attacker's attempts by the replica count, and a deploy resets it.

## D32. Zero-downtime deploys (2026-10-22)
Decided: every documented deploy shape keeps serving through a version change. On one host, two slots (systemd units or Docker containers, blue and green) behind nginx, the one supported front proxy: start the new slot, wait for readiness, switch the upstream, drain and stop the old slot. In containers, rolling updates with readiness probes and a preStop drain. Migrations are expand-only by default; `migrate:validate` refuses destructive or locking changes unless marked `-- keel:contract`, and those ship one release later. `serve` refuses a schema that is behind it but accepts one that is ahead.
Why: a restart-in-place deploy drops requests for the length of a restart and loses in-flight work. SO_REUSEPORT handover was considered and rejected: closing the old listener can reset connections still in its accept queue.
Cost: a proxy in front on single hosts, two ports per app, and discipline in migrations that the validator enforces.

## D33. P2 spike: Jet on database/sql holds; D4 and D23 stand (2026-10-22)
Checked on Postgres 18 (pgx v5 stdlib) and MySQL 9.7 (go-sql-driver, `parseTime`, `loc=UTC`): typed ids bind with `UUID(id)` and scan into `ids.ID[T]` and `*ids.ID[T]`; `jsonb` and `json` round-trip as strings or through a `Scan` method; `text[]` and `uuid[]` work as `pq.StringArray` (a `uuid[]` predicate needs a `::uuid[]` cast); `xid8` row comparison with `pg_snapshot_xmin` works with a cast parameter; joins scan into nested structs; `FOR UPDATE SKIP LOCKED`, `ON CONFLICT DO UPDATE` and `ON DUPLICATE KEY UPDATE` work; `char(36)` ids scan into `uuid.UUID` and typed ids. Amended in the P2 fix pass: Jet's `UUID(id)` binds the zero id as the all-zero uuid, so stores bind typed ids with `id.Param()`, which hands the id to the driver; both drivers call its `Value`, which refuses the zero id.
Decided: keep `database/sql` (D4) and Jet (D23); the pgx-native exit plan is not taken. Generated code goes to `internal/dbgen/<dialect>/{table,model}` through `keel gen`, which uses Jet's generator as a library to map MySQL `char(36)` to `uuid.UUID` and to drop the scratch database's name from MySQL tables. Transactions expose `qrm.DB` (query and exec), not only `qrm.Queryable`, because Jet's `ExecContext` needs it; it is a wrapper, not the `*sql.Tx` (D29).
Cost: `github.com/lib/pq` is linked for its array types through Jet's Postgres package.

## D34. Access changes take effect through a version on the user (2026-10-22)
A process-local principal cache cannot see revocations made on another replica, and a fill racing an invalidation can re-cache old grants.
Decided: `users.access_version` is bumped in the same transaction as every grant, revoke, role-permission change, role deletion, status change and password change. Session lookup joins `users`, so each request reads the current version with no extra query; the principal cache is keyed by (user, realm, version). A browser session whose recorded version differs is rotated (new token and cookie); a bearer session records the new version. API keys are not cached: the key row is read on every request.
Cost: one column and a join on the session lookup; every access change touches the user row.

## D35. Tenancy as built (2026-10-23)
Decided, where the design left room:
- The context's tenant lives in `kit/db` (`db.WithTenant`, `db.TenantOf`), so audit, jobs, files, rate limits and paging read it without importing the optional `kit/tenancy`; lint keeps modules from setting it. `db.InAppTx` opens the tenant transaction when the context has a tenant and a plain one (which sees no tenant's rows) when not, for kit code that serves apps with and without tenancy. `Tx.Tenancy()` tells kit stores the schema carries `tenant_id`.
- Under tenancy, entry to a tenant is a membership: sign-in lands in the host's tenant or the user's default and needs an active membership there instead of a role. Membership and the tenant's state are read on every request (one statement), not cached.
- Kit tables that also hold rows without a tenant keep a nullable `tenant_id` and their `id` primary key; their policies differ by table (tenancy.md section 1), and the operator realm's roles and grants are such rows, readable by the app role only where no tenant is set and written only on the operator pool. Operator-realm sessions and sign-in use the app pool like any realm; only its tenant operations use the operator pool.
- Rows an operator transaction writes for a tenant (tenant creation, audit, jobs fanned out over tenants) name the tenant explicitly, since no setting fills the column default there; in a tenant transaction the policy refuses any other value.
- Package test databases leave the tenancy migrations out, so kit tests run without tenancy on both engines; `testdb.Tenancy(t)` gives one with them.

## D36. App module migrations are written in the app's final shape (2026-10-23)
Kit tables are created plain and made tenant tables by a separate Postgres `_tenancy_` migration, because keel tests every kit package with and without tenancy. Module tables split the same way cannot reference each other: by the time the tenancy file runs, `id` alone is no longer unique, so a child table's foreign key has nothing to point at.
Decided: an app has one dialect and one tenancy choice after `keel init`, so `make:module` and `make:migration` write a module table in its final shape in one file: under tenancy, `tenant_id`, tenant-leading keys, composite foreign keys and the row-level security policy inline. The create-then-alter split stays for kit tables only. Module test databases under tenancy use the tenancy template.
Cost: a module generated in keel itself is tied to keel's mode (Postgres with tenancy); apps regenerate rather than copy.
