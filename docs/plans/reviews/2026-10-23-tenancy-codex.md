# Tenancy review (Codex, session 01a165bb-c8d0-7a70-88b8-c1c0aca0f60a)

## Blockers

1. **Startup role switching can hide a privileged login from `CheckRoles`.**  
   Files: [internal/kit/db/db.go:165](internal/kit/db/db.go:165), [internal/kit/db/db.go:337](internal/kit/db/db.go:337), [internal/kit/tenancy/catalogue.go:324](internal/kit/tenancy/catalogue.go:324), [internal/kit/tenancy/catalogue.go:410](internal/kit/tenancy/catalogue.go:410)  
   Failure scenario: `APP_DATABASE_URL` authenticates as an owner or superuser but includes `options=-c role=keel_app`. Every check observes only `current_user=keel_app` and passes. Application SQL can later execute `RESET ROLE`, recover the authenticated privileged identity, and bypass or disable RLS. Startup options can similarly preset `app.tenant_id`; newly-created connections are not guaranteed to run the reset callback before first use.  
   Fix: reject connection runtime parameters/options that alter `role`, authorization, or any `app.*` setting. Verify the authenticated/session identity as well as `current_user`, require direct login as the app/operator roles, and test `RESET ROLE` explicitly for both pools. The role simulation in [internal/kit/testdb/postgres.go:42](internal/kit/testdb/postgres.go:42) will need corresponding adjustment.

2. **Migration validation permits cross-tenant policies during rollout.**  
   Files: [internal/kit/migrate/validate.go:247](internal/kit/migrate/validate.go:247), [internal/kit/migrate/validate.go:563](internal/kit/migrate/validate.go:563)  
   Failure scenario: `CREATE POLICY open_read ... FOR SELECT USING (true)` on an existing tenant table is ignored because that migration does not add `tenant_id`. When a new table is involved, any permissive all-command policy counts regardless of its expression. The migration can therefore expose every tenant to already-running processes; the later startup catalogue refusal occurs after the unsafe schema is live.  
   Fix: validate all policy DDL, including policies added to existing tables, against the exact tenant expression and allowed exceptions. Prefer also migrating a scratch database and running `CheckCatalogue` before applying production migrations. Add tests for `USING (true)`, missing `WITH CHECK`, and extra permissive policies.

## Should-fix

1. **Session reset is optional even after tenancy is installed.**  
   Files: [internal/kit/db/db.go:220](internal/kit/db/db.go:220), [internal/kit/db/db.go:357](internal/kit/db/db.go:357), [internal/kit/tenancy/tenancy.go:146](internal/kit/tenancy/tenancy.go:146)  
   Failure scenario: a caller opens the database without `db.ResetTenant()` and then calls `tenancy.Install`. Everything appears configured, but a session-level tenant setting can survive commit and reach the next borrower.  
   Fix: make PostgreSQL tenant reset unconditional, or record reset capability on `DB` and have tenancy installation fail when it is absent.

2. **`tenantlint` can be bypassed by multiline SQL or Go strings.**  
   File: [cmd/keel/tenantlint.go:55](cmd/keel/tenantlint.go:55)  
   Failure scenario: scanning each physical line separately misses constructs such as `"SET app." +` followed by `"tenant_id = ..."` or SQL splitting the dotted setting name over lines. That permits code outside the owners to move the session tenant.  
   Fix: scan normalized whole-file token streams while preserving source locations; for Go, inspect constant string expressions. Add multiline and multi-fragment refusal tests.

3. **Self-referencing foreign keys bypass tenant-pair validation.**  
   File: [internal/kit/tenancy/catalogue.go:146](internal/kit/tenancy/catalogue.go:146)  
   Failure scenario: a nullable tenant table with an `id` primary key can add `parent_id REFERENCES same_table(id)`. The catalogue skips it, allowing a tenant A row to reference tenant B; PostgreSQL FK checks do not apply the target table’s RLS policy. Cascades and existence checks then cross the boundary.  
   Fix: enforce `(tenant_id, parent_id) REFERENCES same_table(tenant_id, id)` for self-FKs too, with an explicit reviewed exception if one is genuinely global.

4. **Any table may opt into nullable tenancy without an exception.**  
   File: [internal/kit/tenancy/catalogue.go:121](internal/kit/tenancy/catalogue.go:121)  
   Failure scenario: a new module declares nullable `tenant_id`, an `id` primary key, and the null-safe tenant policy. It passes the catalogue although the spec limits tenantless rows to named kit tables. Rows with `tenant_id IS NULL` become an undeclared global data space.  
   Fix: require an explicit, reasoned nullable-table exception. Default every non-global table to `tenant_id NOT NULL`.

5. **S3 presigning does not verify that the object key belongs to the context tenant.**  
   File: [internal/kit/files/service.go:298](internal/kit/files/service.go:298)  
   Failure scenario: `PublicURL` receives a constructed or operator-loaded `File` for tenant B while the context is tenant A. The presign branch signs `f.Key` directly, unlike `Open`, producing a storage URL that bypasses RLS and `fileshttp`.  
   Fix: apply the same `keyTenant(...) == tenantSegment(ctx)` validation before either URL path and add a two-tenant presign test.

6. **The `fileshttp` API does not enforce its documented host and suspension rules.**  
   Files: [internal/kit/fileshttp/fileshttp.go:68](internal/kit/fileshttp/fileshttp.go:68), [internal/kit/tenancy/http.go:104](internal/kit/tenancy/http.go:104)  
   Failure scenario: a link signed for tenant B is presented on tenant A’s host. `Public` replaces the active tenant with B and invokes `Load`; an ordinary RLS-backed loader serves B’s file. Nothing in the `Loader` contract requires comparing `HostTenant` or refusing suspended tenants. Correctness therefore depends on undocumented external wiring, which was outside this review.  
   Fix: make public-link admission an explicit required callback or typed loader contract that checks shared/own host and current tenant state before switching/loading. Test wrong-host and suspended-tenant links in the kit layer.

7. **`TenantModules` cannot attribute a later tenancy conversion to the table’s owning module.**  
   Files: [internal/kit/migrate/validate.go:113](internal/kit/migrate/validate.go:113), [internal/kit/testdb/testdb.go:183](internal/kit/testdb/testdb.go:183), [db/migrations/postgres/20261022214411_tenancy_notes.sql:4](db/migrations/postgres/20261022214411_tenancy_notes.sql:4)  
   Failure scenario: `notes` is created by the `notes` module and tenantized by the `tenancy` module. `TenantModules` returns `tenancy`, so the non-tenancy test template removes the conversion but retains the `notes` table in its global shape. Tenant-module tests can consequently run against a schema that cannot exist in the tenant build, contrary to D36.  
   Fix: track each altered table back to its creation module and exclude non-kit owner modules, or enforce final-shape app migrations and reject this split pattern.

## Nits

None.

I found no additional issue in API-key locator binding, paging/feed token tenant binding, operator-capability minting, or the job worker’s pool lifecycle. In particular, job claims commit before handlers acquire tenant connections, so I did not find a pooled connection held while waiting for another pool.

**Verdict: fix-then-ship.**

## Fix pass (2026-10-23)

Both blockers were reproduced with a failing test first (`TestPools_CannotSwitchToAPrivilegedRole`: `SET ROLE keel_owner` succeeded and `RESET ROLE` fell back to the superuser login; `TestValidate_PolicyDDL`: every refusal case passed), then fixed.

- B1. Done. Configuration and `db.Open` refuse a Postgres app or operator URL (or `PGOPTIONS`) whose startup parameters set `role`, `session_authorization` or any `app.*` setting, in `options` (`-c`, `-c<name>`, `--name`) or as a parameter. `CheckRoles` requires `session_user` and `current_user` to equal the role each pool's URL logs in as (`DB.LoginRole`, `OperatorAccess.LoginRole`). testdb no longer uses startup options: each run makes its own login roles (members of `<prefix>_app` and `<prefix>_operator`, the operator one with `bypassrls`), opens them through `db.Open`, and drops them at teardown (the janitor drops ones older than a day). Only the pool that migrates templates takes on `<prefix>_owner` with `SET ROLE`, so templates outlive the run. `As`, `TempRole` and `AsRole` make and use per-test login roles. A test runs `RESET ROLE` and `SET ROLE` to every superuser, the owner and (from the app pool) every `bypassrls` role on both pools.
- B2. Done. `migrate.Validate(fsys, dialect, allowed...)` follows tables and policies through every Postgres file and refuses any `create policy` or `alter policy`, on any table, whose result is not the tenant policy (permissive, for all commands, `using` and `with check` each the `=` or `is not distinct from` template, literals compared) unless allowed by table and name with a reason; `drop policy`, `disable` and `no force row level security` on a tenant table. `tenancy.AllowedPolicies` gives the allowlist; `migrate:validate` passes it. No scratch database was added. `TestTenancy_EveryMigrationPassesTheCatalogue` in `internal/app` runs `CheckCatalogue` with the app's exceptions on every migration (kit and modules).
- SF1. Done. `tenancy.Install` returns `ErrNoReset` unless `db.Open` made the pool with `db.ResetTenant`; `tenancy.New` and the app's call sites propagate it.
- SF2. Done. `tenantlint` reads each file whole: Go string literals through `go/scanner` (raw, escaped, joined by `+`), SQL without comments, with line breaks folded, keeping each match's source line. The exact read `current_setting('app.tenant_id', true)` is now allowed in Go too, since `kit/migrate` compares policies against it.
- SF3. Done. The catalogue check pairs `tenant_id` on a tenant table's foreign key to itself; `migrate:validate` refuses a self-reference without it.
- SF4. Done. A nullable `tenant_id` needs `Exception{Table, Nullable: true, Reason}`; the kit's eight such tables are listed. `Exception.Global()` replaces the unexported check (the app's global-table check uses it).
- SF5. Done. `PublicURL` refuses a key of another tenant than the context's before either the presigned or the signed path.
- SF6. Done. `fileshttp.Options.Admit(ctx, tenant)` runs after the link verifies and before its tenant is set; `Public` panics without it. The app's host and suspension check (`linkTenant`) is the callback.
- SF7. Done. `TenantModules` attributes a converted table to the module that created it (except the kit), so the plain template now leaves out `notes` as well as its tenancy conversion.
