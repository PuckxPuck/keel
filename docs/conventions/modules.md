# Adding a module

Start with `go run ./cmd/keel make:module <name>` ([cli.md](../cli.md#generators)): it writes the shape below with an example resource that already passes `make check`, then reshape it.
<!-- part:notes -->
The `notes` module is the worked example.
<!-- /part:notes -->

## How a module is mounted

`internal/app/modules.go` is the one registration point. A module is a package under `internal/modules/<name>` whose `New(Deps)` returns a value implementing `app.Module`:

| Method | Gives the app |
| --- | --- |
| `Permissions(realm) []rbac.Perm` | Its catalogue entries on that realm. Catalogues are built before wiring, so this must not depend on `Deps`. The tenant realm's built-in `admin` role holds them |
| `Register(realm, api)` | Its operations on that realm's API |
| `Mapper(err)` | Its domain errors as problems; installed once per module type |
| `Jobs(q)` | Its job kinds and schedules, registered where the queue is wired |
| `Commands(open)` | Its own `app` commands; `open` opens the database for them, never the operator pool |
| `OperatorCommands(open)` (optional) | Commands that work across tenants; `open` adds the operator pool. Only the tenancy part offers them |

`modules(w)` lists the modules in dependency order, each built from the wiring with only what it uses (`Deps` is declared by the module: realm name, base path, database, audit recorder, cursor keys, job queue, mail and files; modules are built after files are opened). Without a database (route:list, the OpenAPI export) its operations answer 503. Migrations live under `db/migrations` as usual. `make:command` registers app-level commands in `appCommands` beside it.

## Files

1. **Migration.** `keel make:migration <module> create_<table>` (or the one `make:module` writes): the table in every dialect folder per [database.md](database.md), under tenancy in its final shape in that one Postgres file: `tenant_id`, keys and indexes led by it, and row-level security with the tenant policy (D36). Other changes: `keel make:migration <module> <what>`.
   A child table references its parent with a composite foreign key, `foreign key (tenant_id, <parent>_id) references <parents> (tenant_id, id)`, which works because the parent's key was `(tenant_id, id)` from its first migration; add the column and the key to the generated create. The notes module predates this and keeps the kit's create-then-alter split, so it holds its one attachment as columns. Package test databases leave out modules whose tables are tenant tables; their store tests use `testdb.Tenancy(t)` (and `NewTenant`).
2. **Schema types.** `make gen` regenerates `internal/dbgen` (the generators run it for you when a database is reachable).
3. **Store.** `store.go` with the module's queries in Jet, returning domain types. It takes `db.Tx[db.Tenant]` under tenancy, `db.Tx[db.Plain]` without. No `tenant_id` anywhere.
4. **Permissions.** `permissions.go`: `<module>.read`, `<module>.write`, and action permissions (`keel make:permission <module>.<action>`).
5. **Rules.** Pure functions in `rules.go` with table tests first; they return every failing field.
6. **Service.** `service.go`: typed ids, constructor takes only what it uses; every write in `db.InTx` with `audit.Record`; updates match `version` and answer a stale one with `occ.StaleError`; contextual permission checks with `principal.Can`; domain errors as sentinels or typed errors.
7. **Operations.** `module.go` declares each operation with `OperationID`, tags, summary, errors, `Need` and rate-limit class (the realm's body cap applies unless the operation sets its own). `handlers.go` maps input to service calls; `mapError` maps the module's errors to problems.
8. **Cross-module needs.** Declare an interface in this module for what it needs from another; pass the other module's service in through `Deps` in `internal/app/modules.go`.
9. **Jobs and mail.** `keel make:job <module> <kind>`; enqueue inside the service's transaction.
10. **Seed.** Add a step to `internal/app/seed.go` (`db:seed`) if local data helps.
11. **Tests.** The generated three (rule table, store on the database, permission walk through the app), then one integration test per behaviour that matters; the app's walk tests pick up the new operations automatically.
12. **Check.** `make gen && make check`.
