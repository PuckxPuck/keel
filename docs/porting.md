# Porting an existing app

How to move an existing service onto keel. The goal is to keep behaviour and data, and rebuild the code to keel's conventions. Port behaviour, not code: the old app is an executable specification.

## 1. Before writing code

1. **Inventory.** List every route, scheduled task, queue job, mail, file kind, permission or policy, and config value. One table per category in `docs/port/inventory.md`. Count the existing tests per area too: they are the parity list. Nothing is done until every row is mapped or deliberately dropped.
2. **Scope bypasses.** If the old app has tenant or global scopes, list every place that disables them (`withoutGlobalScope`, raw queries, unauthenticated lookups). Each must be re-justified under the new model: most become operator-pool queries, some become a scoped query that never needed the bypass.
3. **Schema.** Dump the current schema. Decide per table: keep, reshape, or drop. Write down every column rename.
4. **Users and sign-in.** How do users sign in today? Password hashes (which algorithm), SSO, API tokens? This decides which providers to keep at init.
5. **Database engine.** Staying on MySQL is fine (`keel init --db mysql`). Moving to Postgres is a data migration on top of the port; do it only with a reason.
6. **Cutover style.** Big bang (small apps, a maintenance window) or strangler (route by path at the proxy, move one area at a time). The strangler needs both apps to read the same database or a sync; prefer big bang when the app is small enough to port in one go.

## 2. Mapping from Laravel

| Laravel | keel |
| --- | --- |
| Routes, controllers | `module.go` operations, `handlers.go` |
| Form Requests | Huma input structs (schema tags for shape and bounds) plus service validation for rules that need the database |
| API Resources | Output structs per operation |
| Eloquent models and queries | Jet queries in the module's `store.go`, on generated table and model types; domain types returned to services |
| Relationships, eager loading | Load the page, then children with one `IN (...)` query, or a join scanned into nested structs; never a query per row |
| Query scopes (`scopeActive`) | Small functions in `store.go` returning a Jet condition (`activeInvoices() BoolExpression`) |
| Policies, Gates | `rbac` catalogue and `Need` per operation; contextual checks (owner, assignee) in the service |
| Spatie roles and permissions | `roles`, `role_permissions`, `user_roles`; import existing assignments with a one-off command |
| Spatie teams mode | `tenancy` memberships with roles granted per tenant |
| Global scopes for tenancy (`BelongsToCompany`-style traits) | Postgres row-level security through `tenancy` ([tenancy.md](tenancy.md)); the scope trait disappears |
| Subdomain tenant resolution middleware | `tenancy` host resolution (`APP_TENANCY_HOST_SUFFIX`, `tenant_domains`) |
| Separate auth guard for an admin portal | A second realm (`operator`) on its own host, with its own cookie and catalogue (D17) |
| Fortify: registration, reset, verification | `auth/password` plus `auth/tokens` flows, mail templates from `mail` |
| Fortify two-factor (TOTP) | `auth/totp`; existing secrets can be imported if they were stored decryptably, otherwise users re-enrol |
| Laravel passkeys | `auth/passkey`; WebAuthn credentials re-register (the stored format differs) |
| Inertia pages with server props | API operations returning the same data; the SPA fetches it. Count props-only pages early: each needs a read endpoint |
| Laravel validation error shape `{message, errors: {field: [...]}}` | problem+json `errors[]` with `location` ([conventions/api.md](conventions/api.md#errors)); rewrite the client's form-error helper once |
| PhpSpreadsheet | `xlsx` |
| bacon QR, barcode packages | `barcode` |
| dompdf, Browsershot | `pdf` (Gotenberg); send fonts and images with each request |
| Decimal casts for money | `money` in minor units (D18); convert in the import |
| Middleware | chi middleware (HTTP-level) or Huma middleware (operation-level) |
| Sanctum or session auth | `auth` sessions (cookie) or bearer tokens from the same table |
| bcrypt passwords | Kept: `auth/password` verifies bcrypt and rehashes to argon2id on the next sign-in. Import the hash column as is. |
| Jobs and queues | `jobs` handlers; dispatch inside the transaction with `queue.Enqueue(ctx, tx, ...)` (no `afterCommit` needed) |
| Task scheduler | `jobs` schedules (cron syntax with a location) |
| Events and listeners | Direct service calls in the same transaction, or a job when the work can be delayed |
| Notifications and Mail | The mail service's `Enqueue` with templates; in-app notifications are a module |
| Storage facade | `files.Storage` (local or S3) with a `Policy` per upload kind |
| Migrations | New goose migrations written to keel's conventions; the old migration history is not replayed |
| Seeders | `app setup` (production-safe defaults) and `app db:seed` (local data) |
| Artisan commands | Subcommands of `cmd/app` |
| `config/*.php`, `.env` | `config` parts with the app's env prefix |
| Observers, model events | Explicit calls in the service; audit through `audit.Record` |
| Soft deletes | Decide per table. keel's default is real deletes with the before image in `audit_log`. Keep `deleted_at` only where users can restore. |
| Pest or PHPUnit feature tests | Integration tests against a real database through the API; keep the old test names as a parity list |
| Telescope, logs | `slog` JSON with request ids; OpenTelemetry if a collector exists |

<!-- part:postgres -->
## 3. MySQL to Postgres

When the port also moves engines, check these before the import, not after:
- **Case-insensitive matching.** MySQL's default collation makes `like` and unique constraints case-insensitive. On Postgres use `ilike` (escaped) for searches and `citext` or a unique index on `lower(x)` for emails, slugs and codes.
- **JSON.** `json` columns become `jsonb`; rewrite JSON-path reads with Postgres operators.
- **Soft deletes and uniques.** A unique on `(tenant_id, name, deleted_at)` does not stop duplicate live rows on Postgres (nulls are distinct). Use a partial unique index `where deleted_at is null`.
- **Locks and deadlocks.** `lockForUpdate` sites become `select ... for update` inside `db.InTx` with retry; Postgres reports serialization failures and deadlocks as retryable errors.
- **Decimal sums.** `sum` over `numeric` returns `numeric`; over minor units it stays `bigint`.
- **Booleans and enums.** `tinyint(1)` becomes `boolean`; MySQL `enum` becomes `text` with a check.
- **Auto-increment ids.** Become UUIDv7 with the old id in `import_ref`.
- **Zero dates.** `0000-00-00` becomes null; decide per column.
- **Bulk loads.** `COPY FROM` is not allowed into tables with row-level security; import with multi-row inserts in batches.
<!-- /part:postgres -->

## 4. Mapping from another Go service

- Move domain code into `internal/modules/<m>`; split handler parsing from rules if they are mixed.
- Replace the old app's config, logging, error and middleware code with kit packages rather than keeping both.
- If the old app used pgx native types (`pgtype.*`, `pgx.Tx`), convert at the store boundary; see D4 in [decisions.md](decisions.md).
- If it used an ORM (GORM, ent), rewrite queries in Jet module by module; the ORM can stay temporarily behind the module's store while tests are added.
- Keep the old OpenAPI or route list as the contract: diff `spec/tenant.openapi.yaml` against it until only intended changes remain.

## 5. Data migration

- Write an `app import` subcommand: reads from the old database (a second connection) or from a dump, writes through the new services or stores in batches, idempotent through an `import_ref` column holding the old primary key.
- Old integer ids become UUIDv7 ids; keep the old id in `import_ref` (unique) so references and re-runs resolve.
- Map statuses and enums explicitly; unknown values fail the import, they are not guessed.
- Timestamps: convert to UTC; record the old app's time zone assumption in the import code.
- Files: copy objects to new keys, record the old path in `import_ref`, verify sizes and hashes.
- Dry-run mode that reports counts and failures without writing. Run it against a copy of production until it is clean.
- Cutover: freeze writes in the old app, final import, smoke test, switch the proxy, keep the old app read-only for a fallback window.

## 6. Parity and done

- **Contract replay.** Record request and response pairs from the old app (a test run, or staging traffic with personal data removed) as [Hurl](https://hurl.dev) files. Run them against the new app in CI; differences are either fixed or listed as intended changes. Ids, timestamps and ordering are captured as variables, not compared literally.
- **Spec.** Once the new spec settles, `oasdiff breaking` guards it against accidental breaking changes.

- Every inventory row has an owner test: an automated test for behaviour, or a note saying how it was checked by hand.
- Compare reports and exports between old and new on the same data.
- Permissions: run the operation walk test for each old role mapped to new roles.
- Performance: run the busiest old queries' equivalents with `explain` on production-sized data, not local data.
