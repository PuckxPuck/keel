# Tenancy

The optional `tenancy` part, for apps that serve several customers (tenants) from one deployment. Postgres only (decision D16). If an app keeps it, every rule here is enforced by tests and a migration lint.

## 1. Model

```
users (global identity) ──< memberships >── tenants ──< tenant_domains
   │                                          │
   └──< user_roles (user, role, tenant) >── roles (per tenant, from templates)
                                              │
                                    every tenant table carries tenant_id
```

- A user is one identity across tenants (one email, one password, one MFA setup). Membership grants entry to a tenant; roles are granted per tenant. A user can be an owner in one tenant and a cashier in another.
- Roles are rows per tenant, created from built-in templates when the tenant is created, then editable by that tenant. The permission catalogue is global code.
- Sub-tenant scopes (branches, outlets, departments) are `rbac` scoped grants inside a tenant, checked in services. Row-level security enforces the tenant boundary only.
- Global tables have no row-level security: `users` and the per-user auth tables (`credentials`, `auth_tokens`, `mfa_*`), `sessions` (with `current_tenant_id`), `passkeys` and `identities` (bound to a realm), `oauth_states` and `auth_challenges` (state made before sign-in), `tenants`, `tenant_domains`, `memberships`, `job_schedules`, `locks`, `rate_counters`, `webhook_deliveries` (inbound) and app-level reference data. Every table in `public` is a tenant table unless it is on the global allowlist (`tenancy.KitExceptions`, and `appGlobalTables` in `internal/app/tenancy.go`) with a reason, and its migration carries `-- keel:global <reason>`; nothing is shared by omission. The app role only reads `tenants`, `tenant_domains` and `memberships`: creating tenants, changing their state, adding and removing members and domains take a `db.Tx[db.Operator]`.
- Every other kit table is a tenant table. Most have `tenant_id not null` with keys `(tenant_id, id)`: `devices`, `device_pairing_codes`, `api_keys`, `files`, `tombstones`, `webhook_endpoints`, `webhook_events`, `webhook_out_deliveries`, `connections`. A few hold rows without a tenant too, so `tenant_id` is nullable and their primary key stays `id` (made in Go); each is a `Nullable` exception in `tenancy.KitExceptions` with its reason:
  - `audit_log`, `jobs`, `mail_outbox`: a row without a tenant is written where no tenant is set (sign-in on a shared host, maintenance) and read only by the operator role.
  - `audit_chain`: one head per chain, keyed by the tenant id (a check keeps `chain_key` and `tenant_id` equal) or `global`; a tenant transaction reaches only its own head, and the global head only where no tenant is set.
  - `api_key_tenants` is the exception the other way: `tenant_id` is not null, but the key is `key_id`, and every row is readable (a presented key is located before its tenant is known, policy `locate`); writes keep the tenant policy.
  - `idempotency_keys`: rows without a tenant are also visible where no tenant is set; a key is scoped by realm and principal as well.
  - `roles`, `role_permissions`, `user_roles`: the operator realm's roles and grants have no tenant. The app role reads them where no tenant is set (operator sign-in) and never writes them; `app setup` and `user:grant --realm operator` write them on the operator pool.
- The tenancy migrations (`<ts>_tenancy_<what>.sql`, Postgres only) change kit tables and carry `-- keel:contract`: the part is chosen at `keel init` and installed on empty tables.

## 2. Request path

1. Realm is chosen by host (tenant hosts vs the operator host).
2. Tenant resolution (tenant realm only), `tenancy.Service.Resolve`: `<slug>APP_TENANCY_HOST_SUFFIX` names a tenant (an unknown slug under the suffix is 404 `tenant_not_found`), else a custom domain from `tenant_domains` when `APP_TENANCY_CUSTOM_DOMAINS`; host lookups are cached for 30 seconds. Otherwise the session's current tenant (`sessions.current_tenant_id`) applies once the session is read. Sign-in on a shared host lands on the user's default membership, else the oldest, skipping suspended tenants (`auth.Tenancy.Admit`). A custom domain may not be the public URL's host, a realm's host, or on or under the host suffix, and is unique; prove ownership before an app lets tenants add their own.
3. `tenancy.Service.Guard`, after the session and before `rbac.Enforce`, reads the tenant and the caller's membership fresh in one statement per request: a signed-in person needs an active membership, else 403 `not_a_member`; then the access state applies (section 6). Under tenancy a sign-in needs a membership in the tenant it lands in instead of a role (a member without roles has no permissions); a non-member gets the same answer as a wrong password. A signed-in person who is not a member still reaches the operations in `Options.AllowNonMember` (sign-out) outside any tenant, and a session whose own current tenant they lost (removed or disabled) drops it and carries on with no tenant, so they can switch to another membership or sign in again; `RemoveMember` also clears it from their sessions. A sign-in on a shared host is recorded as `session.start` on the global trail and, once it commits, `session.entered` on the trail of the tenant it lands in. On a tenant's own host, password reset links go only to that tenant's members, with the same answer either way, so its trail never names anyone else.
4. Application code never filters or fills `tenant_id`: row-level security filters every read, update and delete, and the column default fills every insert. There is no query-builder scope to forget, bypass or get wrong in a join.
5. `tenancy.FromContext(ctx)` is available to everything after the guard; `db.TenantOf(ctx)` is the tenant id kit code reads (`logx` adds `tenant_id` to every log line, `audit` records it, `ratelimit.ByTenant` keys by it, `db.Lock` names are the tenant's own).
6. Tenant code receives a `db.Tx[db.Tenant]`; tenant stores accept nothing else, and only operator-realm modules can open a `db.Tx[db.Operator]` (D29). Kit code that serves apps with and without tenancy opens `db.InAppTx`: a tenant transaction when the context carries a tenant, a plain one (which sees no tenant's rows) when not.
7. Every tenant transaction begins with `select set_config('app.tenant_id', $1, true)` (`tenancy.Install` registers the hook on the app pool). The third argument makes it transaction-local, so a pooled connection never carries a tenant into the next request. Opening one without a tenant in the context fails. `tenancy.Install` (and so `tenancy.New`) fails with `ErrNoReset` unless `db.Open` made the pool with `db.ResetTenant`. `OpenDatabase` installs the hooks whenever the build has the tenancy part, and refuses a database whose tenancy tables disagree with the build either way.
8. Switching tenant is `POST /auth/tenant`: it checks membership, rotates the session (new token, the old one stops working) and drops the user's cached principals. `GET /me/tenants` lists the tenants the user may switch to.

## 3. Database roles

| Role | Rights | Used by |
| --- | --- | --- |
| `<app>_owner` | Owns schema objects; runs migrations | `app migrate` only |
| `<app>_app` | DML on tables; not owner; `nobypassrls` | The tenant realm's pool, jobs running for a tenant |
| `<app>_operator` | DML on tables; `bypassrls` | The operator realm's pool and cross-tenant sweeps only |

`force row level security` makes policies apply to the owner as well, so a migration that reads data also sees only what policies allow (run backfills as the operator role when they must cross tenants). `deploy/db/postgres-roles.sql` creates the three roles; the Postgres container in compose runs the same script. The operator pool is small (`APP_DATABASE_OPERATOR_MAX_OPEN`, default 8, at most `APP_DATABASE_MAX_OPEN`); job workers claim and run on it under tenancy, so configuration refuses one smaller than `APP_JOBS_LANES`' workers plus 2.

Each pool logs in as the role it acts as. Configuration and `db.Open` refuse a Postgres URL (or `PGOPTIONS`) whose startup parameters set `role`, `session_authorization`, `search_path` or any `app.*` setting, in `options` or as a parameter: with a role switched at startup, `RESET ROLE` returns to the login, which no check saw, a preset `app.*` setting would be live before the first reset, and another search path could resolve the app's tables in a schema without the policies. `db.Open` pins both pools' search path to `pg_catalog, public` as a startup parameter, which outranks role and database defaults (nothing can be created through these pools without a schema name; migrations keep the server's search path). The app role is a member of no privileged role, so `SET ROLE` reaches none, and `RESET ROLE` stays the app role; the same holds for the operator role and the owner (a test runs both statements on both pools).

At startup, with the tenancy part, `serve` and every command that opens the database refuse an app pool whose role is, or is a member of (walking role membership), a superuser, a role that bypasses row-level security, a role owning tables in `public` or the operator role; one that may write `tenants`, `tenant_domains` or `memberships`; a view in `public` owned by a role that bypasses row-level security; a database or role default for an `app.*` setting or for `search_path`; a missing operator pool, an operator login without `bypassrls` of its own (it is not inherited), an operator role that is, or is a member of, a superuser or a role that may create roles or databases or replicate, both pools on one role, and a pool whose `session_user` or `current_user` is not the role its URL logs in as (`tenancy.CheckRoles`); configuration refuses an operator URL with the app URL's user. The catalogue check (section 4) runs there too and logs what it finds; the test suite fails on it, and `app migrate` runs it on the migrate connection once the files are applied and exits non-zero on any finding, so a deploy stops before the new release serves.

Without the tenancy part (`notenancy`), configuration and `OpenDatabase` refuse `APP_DATABASE_OPERATOR_URL` and no operator pool is opened. Module commands get the database only (`Opener`); cross-tenant commands come from a module's `OperatorCommands(open OperatorOpener)`, which only the tenancy part calls.

## 4. Schema rules for tenant tables

```sql
create table invoices (
  tenant_id  uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid)
             references tenants(id),
  id         uuid not null,
  number     text not null,
  customer_id uuid not null,
  ...
  primary key (tenant_id, id),
  unique (tenant_id, number),
  foreign key (tenant_id, customer_id) references customers (tenant_id, id)
);
alter table invoices enable row level security;
alter table invoices force row level security;
create policy tenant_isolation on invoices
  using      (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
  with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
```

- `tenant_id` defaults to the transaction's tenant, so inserts never pass it and queries never mention it. With no tenant set the default is null and `not null` refuses the insert: it fails closed. A nullable `tenant_id` needs an exception (`Exception{Table, Nullable: true, Reason}`); the catalogue check refuses one without.
- `tenant_id` first in the primary key and in every index, so lookups and policy checks use the index.
- Unique constraints and foreign keys include `tenant_id`. Constraint checks bypass row-level security, so a global unique on `number` would reveal that another tenant uses that number, and a foreign key without `tenant_id` could point at another tenant's row. That holds for a table referencing itself too: `foreign key (tenant_id, parent_id) references invoices (tenant_id, id)`.
- `nullif(..., '')` because an unset custom setting reads as an empty string once it has been used on a connection. `(select ...)` makes Postgres evaluate it once per query, not per row.
- Soft-deleted rows with a unique name use a partial unique index: `unique (tenant_id, name) where deleted_at is null`.
- Views are created `with (security_invoker = true)`, so row-level security applies to whoever reads them; the catalogue check refuses any other, and startup refuses a view owned by a role that bypasses row-level security (a superuser running migrations makes such views). A `security definer` function skips policies only when its owner bypasses them, but it is still refused unless it is excepted after review: by its schema-qualified signature (`public.keel_migrations_applied()`), with the SHA-256 of its body (`pg_proc.prosrc`) and a reason. An excepted function must also be owned by a role under row-level security (not a superuser, no `bypassrls`), pin its `search_path` in its definition, and not be executable by `PUBLIC`; a changed body fails until the exception's fingerprint is updated, and the error prints the new one.
- `COPY FROM` is refused on tables with RLS; bulk imports use multi-row inserts in batches.
- Nothing outside `kit/db` and `kit/tenancy` may write `app.tenant_id`: `keel lint` (and so `keel check`) fails on `set_config`, `pg_settings`, `SET LOCAL` or the setting's name in any other Go or SQL file. Each file is read whole: a Go file's string literals through `go/scanner` (raw strings and escapes resolved, literals joined by `+` read as one), a SQL file without its comments, with line breaks, string concatenation, quotes, escapes and spaces around the dot taken out (so `SET "app"."tenant_id"`, `"SET app." +` on one line and `"tenant_id"` on the next, `ALTER ROLE ... SET app . tenant_id` and `'app.' || 'tenant_id'` are caught). The one form allowed anywhere is the read `current_setting('app.tenant_id', true)`. Every tenant transaction re-reads the setting before commit and rolls back if it changed (D30). Under tenancy both pools clear the setting each time they hand out a connection (`db.ResetTenant`, one round trip, about 0.2 ms locally), so a session-level `SET` never reaches the next borrower, and startup refuses a database or role default for any `app.*` setting. Lint keeps `tenancy.WithTenant` and `apikeys.TenantTx` inside `kit/db`, `kit/tenancy`, `kit/apikeys` and `internal/app/tenancy.go`, and `db.WithTenant` inside kit code and that file.
- `migrate:validate` fails on a Postgres migration that gives a table a `tenant_id` column without enabling and forcing row-level security and creating the tenant policy in the same file; on any `create policy` or `alter policy`, on any table and in any file, whose result is not the tenant policy (permissive, for all commands, `using` and `with check` each the template's `=` or `is not distinct from` form) unless the table and policy name are allowed with a reason (`tenancy.AllowedPolicies`, from the `Policy` exceptions); on `drop policy`, `disable row level security` or `no force row level security` on a tenant table; and on a tenant table's foreign key to itself without `tenant_id` on both sides. These run before the schema is live, which the startup catalogue check cannot; with the tenancy part present it also follows each table across every file and fails on one that never gets `tenant_id` unless the file that creates it says `-- keel:global <reason>` (the kit's tables are a plain `create table` followed by a `<ts>_tenancy_<table>.sql` that adds the tenant treatment; an app module's table is created in its final shape in one file, D36), and on a marked table missing from the allowlist. Under tenancy it also refuses procedural SQL it cannot read: every `DO` block, and any function or procedure whose body uses `EXECUTE`, `ALTER TABLE`, `CREATE`/`ALTER`/`DROP POLICY` or `ROW LEVEL SECURITY`, unless the file says `-- keel:procedural <reason>` before `-- +goose Up` and the allowlist names the file (for its `DO` blocks) or the function in that file with the same reason (`tenancy.KitProcedural`, and `appProcedural` in `internal/app/tenancy.go`). `tenancy.CheckCatalogue(ctx, tx, exceptions...)` checks the migrated schema: every table not excepted as global has `tenant_id`, row-level security enabled and forced, exactly the tenant policy (permissive, for all commands, `using` and `with check` equal to the template's as Postgres prints them; a nullable `tenant_id` may use `is not distinct from` instead) plus any policy excepted by name, `tenant_id` leading every index (a table whose `tenant_id` is nullable keeps its primary key on `id`), and `tenant_id` on both sides of every foreign key to another tenant table; a global table has no foreign key into a tenant table; views are `security_invoker`; `security definer` functions, in any schema but the system ones, are excepted by signature and body fingerprint (above). Exceptions name a global table, one index, one policy or one function, and need a reason; the kit's are `tenancy.KitExceptions`.
- A composite foreign key on a nullable `tenant_id` (`role_permissions` and `user_roles` to `roles`) is `MATCH SIMPLE`: a row without a tenant (an operator-realm grant) is not checked against `roles` at all. Only the operator role writes those rows; it keeps them consistent, and the rbac loader joins through row-level security.
- `audit_log.seq` is one sequence for the whole platform, so gaps in a tenant's trail show how much other tenants wrote. Treat it as a paging cursor, not a count.

## 5. Kit parts that know about tenants

| Part | Behaviour |
| --- | --- |
| `db` | `InTx[Tenant]` refuses to open without the tenancy hooks or without a tenant in the context; `InAppTx` picks the tenant transaction when the context has a tenant; `Tx.Tenancy()` tells kit stores the schema carries `tenant_id`; `Lock` prefixes names with the context's tenant. |
| `jobs` | `Enqueue` writes the context's tenant (so an operator transaction fanning out over tenants can enqueue for each); the worker claims on the operator pool (`jobs.OperatorTx`) and runs the handler with the job's tenant in its context, so its transactions are that tenant's (`tenancy.Runner` gives handlers a tenant transaction and fails with `ErrNoTenant` without a tenant, never falling back; global work gets `tenancy.OperatorRunner(access)`, which only `internal/app` can build). A job without a tenant runs only when its kind is registered `jobs.Global()` (maintenance, schedules, `mail.send`); any other fails with `no_tenant`. Jobs of a suspended tenant wait (section 6). The open-job unique key is `(tenant_id, unique_key)`. |
| `audit` | Rows carry `tenant_id`: the context's, or `Event.Tenant` when an operator acts on a tenant (the operator stays the actor). The hash chain has one head per tenant (`audit_chain` key), so tenants never wait on each other's writes; `Verify` and `List` read the context's tenant's chain. |
| `ratelimit` | `ByTenant` keys by the context's tenant (`api-tenant`); without tenancy every request shares one bucket. |
| `idempotency` | Rows carry `tenant_id`, which joins the key's scope (`tenant_id, realm, principal, idem_key`). Its prune job runs on the operator pool. |
| `auth` | Sessions record their current tenant; principals are loaded in the tenant's transaction (row-level security returns that tenant's grants only) and cached per tenant. Passkeys and OIDC identities stay global like `users`, bound to the realm they were registered or linked on. Losing the last role in a tenant revokes the sessions working in that tenant. |
| `paging` | Tombstones are per tenant; feed tokens are bound to the tenant that made them. |
| `oauthstate` | The state row records the tenant it started in; `Take` refuses it in any other. |
| `devices` | Devices and pairing codes are tenant rows: pairing and device tokens work on the tenant's host. |

<!-- part:files -->
- `files`: Object keys are `<APP_FILES_KEY_PREFIX>f/<tenant_id>/<shard>/<random>`, so one operator sweep covers every tenant; `Open` refuses a key of another tenant than the context's; signed public links carry and sign the tenant, and `fileshttp.Public` reads the file in it.
<!-- /part:files -->
<!-- part:mail -->
- `mail`: outbox rows carry `tenant_id`; the prune job runs on the operator pool.
<!-- /part:mail -->
<!-- part:apikeys -->
- `apikeys`: see [API keys](#api-keys) below.
<!-- /part:apikeys -->
<!-- part:oidc -->

Tenant-specific configuration of the OIDC callback per realm host is out of scope: OIDC is configured once per app (`APP_OIDC_*`) and works on the realms in `APP_OIDC_REALMS`.
<!-- /part:oidc -->

<!-- part:apikeys -->
### API keys

A presented key names no tenant and its host is the shared api host, so the tenant must come from the key before any tenant transaction opens; under row-level security a tenant-less transaction sees no key row. Resolution is two steps behind `apikeys.Locator` and `apikeys.TxRunner`:

1. `Locate(ctx, keyID)` reads `api_key_tenants (key_id primary key, tenant_id)`: no secrets, no personal data, every row readable (policy `locate`) while writes keep the tenant policy, written in the transaction that creates the key. Unknown id: 401 `invalid_api_key`.
2. The `TxRunner` opens a `db.Tx[db.Tenant]` for that tenant; `Resolve` reads the `api_keys` row there (tenant-scoped, RLS on) and compares the secret. A forged id pointing at another tenant's key finds no row there.

`apikeys.TenantLocator` and `apikeys.TenantTx` implement the two steps; `Create` writes the `api_key_tenants` row in the key's transaction. `ratelimit.ByTenant` keys `api-tenant` by the resolved tenant, the principal carries it (`rbac.Principal.Tenant`) and audit records it. Leak reports name keys of any tenant, so under tenancy the report endpoint revokes in an operator transaction made in `internal/app` and records `apikey.leaked` on the key's tenant's trail; expiry reminders are an operator-pool job (wired with the jobs part). `apikey:*` commands take `--tenant <slug>`. `apikeys.NoTenancy` and the plain `keyTx` (in `internal/app/apikeys.go`) are what an app without tenancy uses. Keys and devices belong to the tenant, not to the member who made them: they keep working after that member is removed (the list shows `createdBy`; `apikey:list` prints it), so revoke them as part of offboarding.
<!-- /part:apikeys -->

## 6. Tenant access state

`tenants.status` is one of:

| State | Effect |
| --- | --- |
| `active` | Normal. |
| `read_only` | Safe methods work; unsafe methods, public ones included (pairing a device), return 403 `tenant_read_only`, except those marked `tenancy.AllowWhileReadOnly()` or named in `Options.AllowReadOnly` (sign-in and sign-out, switching tenant, the second factor, account links, leak reports; billing and export in an app). |
| `suspended` | Every request in the tenant, signed in or not, returns 403 `tenant_suspended`; suspending deletes the sessions whose current tenant it is, and sign-in never lands there. Operators still see the tenant. |

The app decides transitions (for example a billing module moving a tenant to `read_only` when a payment fails) through `tenancy.Service.SetState(ctx, operatorTx, id, state, reason)`, which audits the change on the tenant's trail. Only the operator pool writes tenants. Jobs of a suspended tenant, outbound webhook deliveries included, are not run: the worker puts them back with `run_at` 15 minutes later and the attempt given back, until the tenant is active again.

## 7. Operator realm

- Own hosts (`APP_REALM_OPERATOR_HOSTS`; without them the realm is not served), own cookie (`operator_session`), MFA required (production refuses anything else), idle 30 minutes and absolute 8 hours by default (`APP_REALM_OPERATOR_*`), own permission catalogue (`access.manage`, `tenants.read`, `tenants.manage`, `tenants.suspend`, `users.read`) and built-in `operator` role, made by `app setup` on the operator pool.
- Its operations: `GET /tenants`, `POST /tenants` (tenant, domains, owner membership and roles from the templates in one operator transaction), `POST /tenants/{tenantId}/suspend`, `POST /tenants/{tenantId}/resume`, `GET /tenants/{tenantId}/audit`. They open `db.Tx[db.Operator]` through the capability `internal/app` holds; nothing on the tenant realm receives it. Commands: `tenant:create|list|suspend|resume`.
- Its sessions and sign-in run on the app pool like any realm's (users and sessions are global); a passkey registered on the tenant realm never satisfies its MFA.
- "View as tenant" for support (a time-limited, read-only session in the tenant realm, audited as on-behalf-of) is not built yet.

### Leaving tenancy out

Every use of `kit/tenancy` in `internal/app` is in `internal/app/tenancy.go` (`//go:build !notenancy`); `tenancy_off.go` (`//go:build notenancy`) has the same hooks as no-ops (no tenant middleware, plain job and maintenance transactions, `--tenant` refused). Other parts reach tenancy only through those hooks and `Deps.Tenancy`: the apikeys part, for one, locates and checks keys in their tenant when `Deps.Tenancy` is set and in one plain transaction when not, and its leak and tenant tests carry `!notenancy && !noapikeys`. Every optional part follows the same pattern ([architecture.md](architecture.md#12-optional-parts)). `keel check` vets `-tags notenancy` (with `nonotes`, since the example module needs tenancy) so the off build keeps compiling; `keel init` deletes the on file and drops the tag from the twin when an app leaves the part out.

## 8. Tests

- Tests log in as the run's own login roles, members of `<prefix>_app` and `<prefix>_operator`, through `db.Open` like an app: no startup role switch. Only the pool that migrates templates takes on `<prefix>_owner` with `SET ROLE`, so templates outlive the run. Package databases leave the tenancy migrations out, and with them every module with a tenant table (the module that created the table, even when a tenancy file converts it later), so kit tests run as an app without tenancy on both engines; `testdb.Tenancy(t)` gives a Postgres database with all of them and the operator capability, `NewTenant(t, slug)` adds a tenant, `As(t, role)` logs in as a new member of another role and `TempRole`/`AsRole` make and use a login role, to test misconfiguration.
- Catalogue test (section 4): `TestTenancy_EveryMigrationPassesTheCatalogue` in `internal/app` runs `CheckCatalogue` with the app's exceptions on every migration, kit and modules; keep it in every app.
- Isolation walk: two tenants with the same data; every operation called in tenant A with tenant B's ids returns 404 and changes nothing.
- Unset tenant: a transaction on the app pool with no tenant sees zero rows in every tenant table.
- Jobs: a job enqueued in tenant A runs with tenant A set and cannot touch tenant B.
- Operator: the operator pool sees both tenants; the tenant realm cannot reach operator routes on its host.
