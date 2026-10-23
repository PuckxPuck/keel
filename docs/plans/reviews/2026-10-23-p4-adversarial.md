# P4 tenancy: adversarial review (2026-10-23)

Scope: break tenant isolation in P4 as a tenant member, an API key holder, a member of two tenants, a suspended or read-only tenant's member, and an app developer making a plausible mistake; probe the database layer directly. Every finding below was reproduced with a probe test on Postgres 127.0.0.1:5442 via `go test -overlay` (probe files in the session scratchpad, `adv/`: `kit_adv_test.go` overlaid into `internal/kit/tenancy`, `app_adv_test.go` and `app_adv2_test.go` into `internal/app`, `mig_adv_test.go` into `internal/kit/migrate`, `lint/main.go` standalone). No repo code was edited.

Verdict: **fix-then-ship**. The request path holds: no HTTP operation in `internal/app` let one tenant read or change another's rows. The database layer holds under connection reuse. The gaps are in the guard rails around developer mistakes, which is where D16 promises "fails closed": two fail open (B1, B2).

## Blockers

### B1. A tenant table written without `tenant_id` passes every check and is shared by all tenants
- Where: `internal/kit/tenancy/catalogue.go:103-107` (only tables that have a `tenant_id` column are examined), `catalogue.go:22-30` (`KitExceptions` lists only global tables that carry `tenant_id`), `internal/kit/migrate/validate.go:419-453` (only `create table` statements that mention `tenant_id` are checked).
- Attack: a developer adds `create table invoices (id uuid primary key, number text not null)` and stores tenant data in it. Nothing has RLS; every tenant reads and writes every row.
- Probe: `TestAdv_CatalogueBlindSpots` (part 1): `CheckCatalogue = <nil>`. `TestAdv_ValidateBlindSpots`: `migrate.Validate = <nil>` for the same file.
- This is also drift from the brief addendum: "Global tables (no tenant_id, no RLS, listed explicitly in the catalogue check's allowlist with a reason)". Only global tables that record a tenant are listed today.
- Fix: invert the check. Under tenancy, every table in `public` is a tenant table unless it is on the allowlist: add `users`, `credentials`, `auth_tokens`, `mfa_*`, `sessions`, `passkeys`, `identities`, `auth_challenges`, `tenants`, `job_schedules`, `locks`, `rate_counters`, `audit_chain`, `webhook_deliveries` to `KitExceptions` with reasons, and let apps pass their own. `CheckCatalogue` reports any table without `tenant_id` that is not listed. In `migrate.Validate`, when the tenancy migrations are present, a `create table` without `tenant_id` needs `-- keel:global`.

### B2. `tenancy.Runner` turns a missing tenant into the operator pool
- Where: `internal/kit/tenancy/tenancy.go:188-197`; recommended in `docs/packages.md:180` ("job handlers, kit services") and `docs/tenancy.md` section 5 (`jobs` row).
- Attack: a job handler or kit service wired with `Runner` gets a context without a tenant. That happens when a handler detaches work with `context.Background()`, when a public route on a host that names no tenant calls the service, or when a link or token without a tenant reaches it. It then gets a `Tx[Operator]` with `bypassrls`, and sees and changes every tenant's rows. No error is raised.
- Probe: `TestAdv_RunnerFallsBackToOperator`: with the tenant, 1 role row; with `context.Background()`, 2 rows (both tenants).
- No in-tree caller exists today, so nothing is exploitable in this repo yet. It is still the kit's documented pattern for P5 wiring, and it is the failure mode D16 exists to prevent.
- Fix: split it. `Runner` opens a tenant transaction and returns `ErrNoTenant` without a tenant. Global work (kinds registered `jobs.Global()`, sweeps) gets a separate `OperatorRunner(access)` that is wired explicitly in `internal/app`. The worker passes the right runner by kind, so a tenant kind can never get the operator pool.

## Should-fix

### S1. Global tables that record a tenant are writable from any tenant transaction
- Where: `20261022192140_tenancy_tenants.sql:15-31` (the app role keeps UPDATE on every tenant row), `20261022192143_tenancy_memberships.sql` (no RLS, full DML), `audit_chain`, `sessions`, `api_key_tenants`. In Go, `tenancy.AddMember`/`RemoveMember` (`internal/kit/tenancy/store.go:166-185`) and `Service.SetState` (`service.go:139`) accept any `db.Transaction` and any tenant id.
- Attack: inside tenant A's transaction, code (for example an "invite teammate" or "rename workspace" feature that takes an id from the request) runs `UPDATE tenants ... WHERE id = B`, `INSERT INTO memberships (B, attacker)`, disables B's members, or rewrites B's audit chain head.
- Probe: `TestAdv_GlobalTablesWritableFromATenant`: from acme's transaction, 1 row each: globex renamed and made read-only, ann inserted as a globex member (`IsMember` true), bob's globex membership disabled, globex's `audit_chain` head overwritten. `SetState` itself fails closed today only because its audit row trips the `audit_log` policy, which is incidental.
- Fix: enable RLS on `tenants` and `memberships`, plus `audit_chain` keyed by its tenant key. Use a `for select using (true)` policy and write policies `using/with check (tenant_id = setting)` (`id = setting` on `tenants`). Sign-in reads still work, the operator pool bypasses, and a tenant transaction can only touch its own row. Make `AddMember`/`RemoveMember` take `Tx[Operator]`, or read the tenant from `db.TenantOf` instead of a parameter.

### S2. Plain transactions are not pinned, so a session-level SET survives on the pooled connection
- Where: `internal/kit/tenancy/tenancy.go:150-186` registers hooks for the `Tenant` scope only; the lint is `cmd/keel/tenantlint.go:18-19`.
- Attack: `SET "app"."tenant_id" = '<B>'` or `SET app . tenant_id = '<B>'` in any transaction. Both are session-level, and neither is matched by the lint. A plain transaction has no before-commit check, so it commits, and every later plain transaction on that connection (guard, host resolution, `TenantLocator`, sign-in, operator-realm principal loading) runs as tenant B. Tenant transactions are unaffected because their local set wins.
- Probe: `TestAdv_SessionLevelSetLeaksToNextBorrower` (pool of one connection): the next borrower reads `setting = <B>` and sees B's role rows in a plain transaction. The value is still there after a tenant transaction. `lint/main.go`: lint `flagged=false` for `SET "app"."tenant_id"`, `SET app . tenant_id` and `SET SESSION "app".tenant_id`.
- Fix: under tenancy, register `OnBegin[Plain]` running `select set_config('app.tenant_id', '', true)` and `BeforeCommit[Plain]` checking that it is still empty. Then every app-pool transaction is deterministic whatever the session state. Widen the lint to `\bset\b[^;]*\bapp\b"?\s*\.` and `pg_settings`. See S3 for `SET ROLE`.

### S3. `CheckRoles` misses role membership and superuser-owned schema objects
- Where: `internal/kit/tenancy/catalogue.go:207-261`.
- Attack 1: the app role is granted membership in the operator (or owner) role, for example to share privileges on a managed host. `CheckRoles` passes. Any code that runs `SET ROLE <operator>` (not matched by the lint, and session-level) bypasses RLS for that connection and every later borrower.
- Probe: `TestAdv_AppRoleMemberOfOperator`: `CheckRoles = <nil>`; after `set role` in one plain transaction, a later tenant-A transaction on the same connection sees 2 tenants' roles.
- Attack 2: migrations run as a superuser (`APP_DATABASE_MIGRATE_URL=postgres://postgres@...`, common on managed hosts). Any view or `security definer` function they create skips every policy, and nothing reports it.
- Probe: `TestAdv_SuperuserViewLeaks`: tenant A reads both tenants' roles through a superuser-owned view; `CheckCatalogue` and `CheckRoles` both `<nil>`.
- Fix: refuse an app role that can reach any superuser, `bypassrls` or table-owning role (`pg_has_role(current_user, oid, 'MEMBER')` over `pg_roles`). Refuse public tables owned by a superuser or `bypassrls` role. Make `CheckCatalogue` flag views over tenant tables without `security_invoker` and `security definer` functions in `public` (allowlisting `keel_migrations_applied`). Have the tenant `BeforeCommit` hook also check `current_user = session_user`.

### S4. The catalogue check accepts policies that only mention the setting, and extra permissive policies
- Where: `internal/kit/tenancy/catalogue.go:136-151` (passes if any `ALL` policy's text contains `current_setting('app.tenant_id'`), `migrate/validate.go:441-443` (any `create policy` counts).
- Attack: the template policy plus `create policy everyone_reads on notes for select using (true)`, or `using (tenant_id = setting or true)`. Permissive policies are OR'd.
- Probe: `TestAdv_CatalogueBlindSpots` (parts 2 and 3): `CheckCatalogue = <nil>`, and acme reads globex's note.
- Fix: require exactly the template predicate (`pg_get_expr` normalised and compared with the template's, or `tenant_id = (SELECT ...)` / `IS NOT DISTINCT FROM` only). Report every other permissive policy on a tenant table unless it is excepted by name (the kit's `global_read` policies). In `Validate`, require the policy to be `for all` (no `for` clause).

### S5. A read-only tenant still accepts public writes into tenant tables (device pairing)
- Where: `internal/kit/tenancy/http.go:189-191` lets every public operation through in read-only; `internal/app/devices.go:81-82` registers `pairDevice` as public.
- Attack: a member makes a pairing code; the tenant goes read-only (payment failed); the code is redeemed and a device row is written.
- Probe: `TestAdv_ReadOnlyTenantStillPairsDevices`: signed-in write 403 `tenant_read_only`, public pairing 200.
- Fix: exempt sign-in and other operations that do not write tenant data by name (`Options.AllowReadOnly`), not by "public"; or mark `pairDevice` as not allowed. A public operation that writes tenant rows should be refused like any other unsafe one.

### S6. Account-existence oracle through the caller's own tenant audit trail
- Where: `internal/app/auth.go:400-415`. `requestReset` runs in the host's tenant transaction and audits `password.reset_requested` with the user id only when the address exists. The same pattern applies to `resetPassword`, `acceptInvite` and `verifyEmail` (their audit and `RevokeUser` rows land in whichever tenant's host served the link).
- Attack: an owner of tenant B posts reset requests for addresses on B's own host, anonymously. B's trail gains a row naming the user id of every address that has an account anywhere on the platform, which defeats the request floor and the constant answer. Today only operators read trails, but `audit.List` is built to serve a tenant's own trail.
- Probe: `TestAdv_ResetRequestLandsInTheCallersTenant`: globex's trail gains `password.reset_requested user <ann's id>`; the unknown address adds nothing. Not probed: the reset mail is handed to the notifier inside globex's transaction, so a mail outbox row would carry globex's tenant, and a notifier that brands by tenant would send globex-branded mail to acme's users.
- Fix: record user-global events with no tenant (`audit.Event` with an explicit global marker, or run these handlers in a plain transaction). They belong to the user, not to the host's tenant.

### S7. A tenant's custom domain can claim the shared host (or another realm's host)
- Where: `internal/kit/tenancy/service.go:95-102` accepts any host with a dot.
- Attack: a tenant created with `domains: ["app.example.test"]` (the shared host) with `APP_TENANCY_CUSTOM_DOMAINS=true`. Once the 30 s host cache turns over, every shared-host request runs in that tenant: other tenants' users cannot sign in there, and that tenant's sign-in page owns the shared host. The input is operator-only today, but self-service domains are the usual next feature.
- Probe: `TestAdv_CustomDomainTakesTheSharedHost`: creation succeeds; on a fresh handler ann (acme) gets 401 on the shared host and the owner of "evil" signs in there.
- Fix: refuse domains under `APP_TENANCY_HOST_SUFFIX`, equal to `APP_PUBLIC_URL`'s host or any configured realm host (tenant, api, operator), and say in `docs/tenancy.md` that domains need ownership proof before an app lets tenants add them.

### S8. `tenancy.WithTenant` goes around the `db.WithTenant` lint
- Where: `.golangci.yml:44-46` forbids `db.WithTenant` outside kit and `internal/app`; `internal/kit/tenancy/tenancy.go:98-102` exports `WithTenant`, which calls it.
- Attack: a module does `tenancy.WithTenant(ctx, tenancy.Tenant{ID: idFromRequest})` and opens a `Tx[Tenant]` in a tenant it was never admitted to. Lint is silent. This is a code-reading finding; golangci-lint has no overlay, so it was not run.
- Fix: add `^tenancy\.WithTenant$` (package `internal/kit/tenancy`) to the same forbidigo rule and exclusion.

## Nits

- `docs/tenancy.md:74` says views and `security definer` functions "run as their owner and skip policies". With a `nobypassrls` owner and forced RLS they do not (probe: owner-made view and definer both returned acme's row only). The real risk is a superuser or `bypassrls` owner (S3). Reword.
- `20261022192147_tenancy_role_permissions.sql:8` and `20261022192148_tenancy_user_roles.sql:12`: composite foreign keys on a nullable `tenant_id` are `MATCH SIMPLE`, so rows without a tenant skip the check entirely. An operator-pool row can point at any tenant's role. It is harmless today because the loader joins through RLS, but add a plain `foreign key (role_id) references roles (id)` beside it.
- `catalogue.go:29`: the reason "seq is an identity no caller chooses, so it reveals nothing" is not quite true. `audit.Entry.Seq` is in the JSON and is global, so gaps reveal platform-wide activity to whoever reads a trail. Use a per-chain position for paging, or reword.
- Jobs, outbound webhooks and mail of a suspended tenant keep running (the worker does not read tenant state). Decide and document.
- API keys and devices made by a member keep working after the member is removed (probe: key 200 after `RemoveMember`). They are tenant principals, so this may be intended; `docs/tenancy.md` does not say.
- Not probed, from reading the code: an OIDC sign-in started on a tenant host records that tenant in `oauth_states` and cannot finish on `APP_PUBLIC_URL`'s callback (`oauthstate.go:151-160`). This fails closed, but it means OIDC works only from the shared host.

## Attacks the code withstood

- Connection reuse (pool of one connection, so the same backend each time): a panic in a tenant transaction; a context cancelled mid-query (`pg_sleep`); a context cancelled after work but before commit; the before-commit refusal; a failed commit (deferred unique violation); a savepoint released with a moved setting (caught at commit). After each, the next plain borrower read an empty setting and saw 0 tenant rows. A savepoint rollback restores tenant A inside the transaction.
- Column default override: tenant A inserting `tenant_id = B` or `NULL`, updating its rows to `tenant_id = B`, and a plain transaction inserting an operator-realm role all fail with 42501. `audit.Record` under a derived `db.WithTenant(ctx, B)` inside A's transaction is refused by the `audit_log` policy.
- HTTP, signed-in member of A with B's ids: the existing isolation walk (key revoke, device rotate and revoke). Also: B's pairing code on A's host and on the shared host (422); B's API key as a bearer on A's tenant host (401); the API key of a suspended tenant (403 `tenant_suspended`).
- Member of both tenants: the same `Idempotency-Key` in A and B gave two keys with no replay. 30 in-flight requests on the old cookie racing a switch never listed B's rows, and the old token answered 401 once rotated. The principal cache is keyed by tenant.
- Removed member: her session got 403 `not_a_member` at once; a stale shared-host session rotated out (401) and a fresh sign-in landed in her other tenant.
- API key resolution: a forged key id pointing at B's key is read in B's transaction and fails the secret compare. A key never resolves on the tenant realm.
- Schema: every unique key and foreign key on a not-null tenant table includes `tenant_id`, so `ON CONFLICT` cannot meet another tenant's row. The only `security definer` in `public` is `keel_migrations_applied` (pinned `search_path`, not a tenant table), and the only sequence is `audit_log_seq_seq`.
- From reading the code: `files.Open` refuses another tenant's key; public links sign the tenant; feed tokens and `oauthstate.Take` are bound to the tenant; `jobs.Enqueue` writes the context's tenant and the policy refuses a mismatch; a job without a tenant of a non-global kind fails `no_tenant` (existing test).

## Verification

- `go test -race -count=1 ./internal/kit/tenancy ./internal/app ./internal/kit/db ./internal/kit/apikeys ./internal/kit/auth/...` on Postgres only: all ok.
- `go build ./...` fails in `cmd/keel` (`make.go:128: undefined: runGenIn`; earlier `scaffold.go:21` embed of a missing `templates` dir). Another session is editing `cmd/keel`, so `keel check` and the lint step could not be run. The lint regex was tested standalone instead.
- Probe results are quoted in each finding. The probes are written as tests, so each can be committed (inverted) as the regression test for its fix.

## Fix pass (2026-10-23)

Each probe was run against the code first and showed the leak, then again after the fix.

- B1. Done. Every table in `public` is a tenant table unless the allowlist names it global with a reason. `CheckCatalogue` and `migrate.Validate` (across files, once the tenancy part is present) both refuse an unlisted table without `tenant_id`, and `migrate:validate` checks marked tables against the allowlist. Probe: `invoices` is reported by both.
- B2. Done. `tenancy.Runner(d)` returns `ErrNoTenant` without a tenant. Global work gets `tenancy.OperatorRunner(access)`, which only `internal/app` can build. Probe: the runner refuses `context.Background()`.
- S1. Done. The app role has SELECT only on `tenants`, `tenant_domains` and `memberships`, and their writes take `db.Tx[db.Operator]`. `audit_chain` has row-level security keyed by a new `tenant_id` (a check keeps it equal to `chain_key`); the global head is usable only with no tenant set. `api_key_tenants` has the tenant policy plus a `locate` policy that keeps reads open. Probe: every write is refused or changes 0 rows.
- S2. Done with a different mechanism, as decided: the pools clear the setting on every checkout (about 0.18 ms, one round trip), and the lint catches every form in the probe. Probe: the next borrower reads an empty setting and sees 0 rows.
- S3. Done. `CheckRoles` walks role membership and refuses a view owned by a superuser or `bypassrls` role. `CheckCatalogue` refuses views without `security_invoker` and unlisted `security definer` functions. The `current_user = session_user` commit check was not added (testdb connects as the admin with `-c role=`, and membership is refused at startup). Probe: both checks now refuse.
- S4. Done. The policy expressions are compared exactly, and extra policies fail unless excepted by name. `migrate.Validate` counts only a permissive `for all` policy. Probe: refused in both places.
- S5. Done. Read-only refuses public unsafe operations too, unless allowed: sign-in and sign-out, switching tenant, the second factor, account links and leak reports. Probe: pairing answers 403 `tenant_read_only`.
- S6. Done in the decided form. On a tenant's host, reset links go only to that tenant's members, with the same answer either way, and a reset link for a non-member is invalid there. Probe: globex's trail gains nothing for ann.
- S7. Done. A custom domain may not be the public URL's host, a realm's host, or on or under the host suffix, and stays unique. The probe as written still succeeds because its "shared host" is not configured anywhere (`APP_PUBLIC_URL` is localhost and the tenant realm has no hosts). With `APP_PUBLIC_URL` naming it, creation fails with `ErrInvalid` (`TestTenancy_CustomDomainsAreChecked`).
- S8. Done (forbidigo, see the Opus review item 4).
- Nits:
  - `docs/tenancy.md` on definer functions and views is corrected.
  - The MATCH SIMPLE behaviour and the platform-wide `audit_log.seq` are documented.
  - Jobs of a suspended tenant, outbound webhook deliveries included, are put back 15 minutes later with the attempt given back.
  - API keys and devices belong to the tenant and survive member removal; this is documented, and `apikey:list` prints the creator.
  - OIDC from tenant hosts is unchanged.
