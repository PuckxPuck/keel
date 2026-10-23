# Database conventions

An app runs on Postgres (18 current, 17 supported) or MySQL (9.7 LTS current, 8.4 LTS supported), chosen at `keel init`. Rules below apply to both unless a column says otherwise.

## Connections
- Postgres through `pgx/v5/stdlib`; MySQL through go-sql-driver with `parseTime=true`, `loc=UTC`, `multiStatements=false`.
- Every connection runs in UTC with timeouts set: Postgres `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`; MySQL `time_zone='+00:00'`, `innodb_lock_wait_timeout`, strict `sql_mode`.
- Production verifies TLS. Three roles where the host allows: owner (migrations), app (runtime, not owner), and with tenancy an operator role that bypasses row-level security ([../tenancy.md](../tenancy.md#3-database-roles)). Production requires `APP_DATABASE_MIGRATE_URL` with a different user from `APP_DATABASE_URL`, so the app never owns its tables. `deploy/db/postgres-roles.sql` takes the passwords as psql variables, resets on every run any role attribute that would escape row-level security (superuser, createdb, createrole, replication, and bypassrls except on the operator), grants the app and operator roles SELECT, INSERT, UPDATE and DELETE on every owner-created table by default. Append-only tables revoke UPDATE and DELETE in their own migrations (on Postgres; `audit_log` does). MySQL grants are per user and outside migrations, so there the operator grants the app user table-level privileges with only SELECT and INSERT on `audit_log` (a database-wide grant cannot be narrowed for one table). No migration or check enforces that on MySQL, so the grant is the operator's to get right.
- goose's version table lives in its own schema, `keel_migrations.goose_db_version`, which `app migrate` creates as the owner; the app and operator roles have no access to it. They read the applied versions only through `public.keel_migrations_applied()` (security definer, search path pinned, created by a kit migration; EXECUTE is revoked from PUBLIC and granted to `keel_app` and `keel_operator`), which `serve` uses for its startup schema check. On MySQL the table stays in the app database.
- No transaction-mode pooler in front of Postgres unless prepared statements are disabled for it.

## Migrations
- goose SQL in `db/migrations/<dialect>/` (one directory per dialect while keel holds both; `keel init` keeps one), named `<UTC timestamp>_<module>_<what>.sql`; create with `keel make:migration <module> <what>` (every dialect folder, the table template for `create_<table>`) or `go tool -modfile=tools/go.mod goose -dir db/migrations/<dialect> create <module>_<what> sql`, so the timestamp is real. `app migrate:validate` checks names, Up and Down, one statement per file on MySQL, and contract changes. It splits files with goose's own rules (restated in `migrate`, since goose keeps its parser internal), then into the statements the server runs, so comments, literals, dollar quotes and two statements on one line count as they execute. Contract changes: any drop except `drop index concurrently`, truncate, rename, `alter type`, column type changes, `set not null`, `drop default`, a not-null column without a default, `vacuum full`, and on Postgres an index on an existing table without `concurrently` or a foreign key or check added without `not valid`. Mark a contract migration with `-- keel:contract` on a comment line before `-- +goose Up`.
- Each file has `-- +goose Up` and `-- +goose Down`; Down must work locally.
- One table or one change per file. On MySQL, exactly one statement per file (DDL commits implicitly, so a failure mid-file leaves half a change).
- Append-only once merged. Fix forward. Never wipe or reset a shared database.
- Safe for the running release (expand and contract): see [../operations.md](../operations.md#migrations-in-deploys).

## Types

| Purpose | Postgres | MySQL | Go |
| --- | --- | --- | --- |
| Id, foreign key | `uuid` | `char(36) character set ascii collate ascii_bin` | `uuid.UUID`, `*uuid.UUID` |
| Instant | `timestamptz` | `datetime(6)` (stored UTC) | `time.Time` |
| Calendar date | `date` | `date` | `dates.Date` |
| Text with a bound | `text` + `check (char_length(x) <= n)` | `varchar(n)` | `string` |
| Long text | `text` | `text` or `mediumtext` | `string` |
| Status, kind | `text` + `check (x in (...))` | `varchar(32)` + `check (x in (...))` | named constants |
| Money amount | `bigint` (minor units) | `bigint` | `money.Amount.Minor` (`int64`) |
| Currency | `char(3)` | `char(3)` | `money.Amount.Currency` |
| Rate, percentage, fractional quantity | `numeric(p,s)` | `decimal(p,s)` | `decimal.Decimal`, never float |
| Case-insensitive text (slugs, codes) | `citext`, or `text` with a unique index on `lower(x)` | default collation is already case-insensitive | `string`, normalised on write |
| Email | `text` with a unique index, compared exactly | `varchar(254) collate utf8mb4_bin`, compared exactly | normalised on write (trim, lower case, NFC): `users.NormaliseEmail` |
| Count | `integer` + `check (x >= 0)` | `int` + check | `int` |
| Flag | `boolean` | `boolean` (tinyint) | `bool` |
| Structured payload | `jsonb`, validated in Go | `json`, validated in Go | typed struct |
| Hash | `bytea` | `varbinary(32)` | `[]byte` |

Never database enum types: changing them needs DDL on both engines in different ways.

## Tables
- `id` primary key, UUIDv7 made in Go. Human codes (`order_no`) are separate unique columns.
- `created_at`, `updated_at` on every table. User-written tables add `created_by`, `updated_by` referencing `users(id)`. `updated_at` is set by the update query from the business clock so tests can pin it.
- Editable rows: `version integer not null default 1`; updates are `where id = ? and version = ?` and bump it; zero rows affected is stale.
- Foreign keys on every reference, with an index on each referencing column (Postgres does not create one; MySQL does). `on delete cascade` only for owned children; otherwise restrict.
- History tables are append-only: no update or delete queries.
- No soft deletes by default; the audit log keeps the before image. Add `deleted_at` only where users restore.
- `import_ref` (unique, nullable) on tables filled from another system.
<!-- part:tenancy -->
- With tenancy: every tenant table follows [../tenancy.md](../tenancy.md#4-schema-rules-for-tenant-tables) (`tenant_id not null` and first in keys and indexes, composite unique and foreign keys, a self-reference included, RLS enabled, forced, with the tenant policy, all in the migration that adds the column; `migrate:validate` checks it, refuses any other policy unless it is allowed by name with a reason, and refuses dropping a tenant table's policy or turning its row-level security off). Every other table is global only on purpose: its migration says `-- keel:global <reason>` and it is in `appGlobalTables` (`internal/app/tenancy.go`) with the same reason; a table with neither fails `migrate:validate`. Views are created `with (security_invoker = true)`. Procedural SQL (a `DO` block, or a function whose body runs `EXECUTE` or changes tables, policies or row-level security) needs `-- keel:procedural <reason>` before `-- +goose Up` and an entry in `appProcedural` (`internal/app/tenancy.go`) with the same reason; `app migrate` checks the migrated schema against the tenancy rules and fails on a finding.
<!-- /part:tenancy -->
- A money column is always paired with its currency column, or the table documents the single currency it uses.

## Queries (Jet)

Queries are written in Go with [Jet](https://github.com/go-jet/jet), a type-safe query builder whose table and model types are generated from the migrated schema (decision D23). A misspelled column or a type mismatch fails to compile. There is no ORM runtime: no reflection-driven lazy loading, no hidden queries, no hooks.

Where things live:
- `internal/dbgen/<dialect>/table` and `internal/dbgen/<dialect>/model` hold Jet's generated types (never edited). `make gen` migrates a scratch database per engine and regenerates them. On MySQL it maps `char(36)` columns to `uuid.UUID` and writes tables without a database name, so they work in any database.
- Each module has `store.go`: the only file in the module that builds queries. Functions take the transaction (`db.Tx[db.Plain]`, or `db.Tx[db.Tenant]` under tenancy), run Jet statements against `tx.Q()`, and return domain types, not Jet models.

```go
func (s *Store) Invoice(ctx context.Context, tx db.Tx[db.Plain], id InvoiceID) (Invoice, error) {
    stmt := SELECT(Invoices.AllColumns).
        FROM(Invoices).
        WHERE(Invoices.ID.EQ(id.Param()))
    var m model.Invoices
    if err := stmt.QueryContext(ctx, tx.Q(), &m); err != nil {
        return Invoice{}, db.NotFoundOr(err, ErrInvoiceNotFound)
    }
    return toInvoice(m), nil
}
```

Rules:
- Tenant scoping is never written in a query. Row-level security filters reads, updates and deletes, and the `tenant_id` column default fills inserts ([../tenancy.md](../tenancy.md#4-schema-rules-for-tenant-tables)). Insert column lists come from `db.Insertable(Invoices.AllColumns)`, which leaves out `tenant_id` and other database-filled columns; if one slips in, the policy's `with check` refuses the row, so a mistake fails closed.
- Optional filters are built conditionally in Go: start from `Bool(true)` and `AND` each filter that is set. Filter values are always bound parameters, never concatenated.
- Lists of ids: `Invoices.ID.IN(ids...)` (Jet renders the right form per dialect).
- Case-insensitive search: Postgres `ILIKE` with escaped input (or `citext` columns); MySQL `LIKE` under its default collation. `db.LikeEscape` escapes `%`, `_` and `\`.
- JSON: Postgres `jsonb` operators; MySQL `json` with `->>`; raw fragments only through Jet's `Raw` with bound arguments, inside the store.
- Sums of `numeric` come back as decimals; sums of minor units stay `bigint`. Scan into explicit types.
- Select the columns the caller needs; `AllColumns` is fine for single-row reads of the module's own table.
- Locks: `.FOR(UPDATE())` for read-then-write; queue-style reads `.FOR(UPDATE().SKIP_LOCKED())`.
- Counters and "next number": insert the counter row if missing, then lock it with `FOR UPDATE` or `UPDATE ... SET n = n + 1` and read it in the same transaction. Never `max(x) + 1`.
- Upserts: Postgres `ON_CONFLICT(...).DO_UPDATE(...)`; MySQL `ON_DUPLICATE_KEY_UPDATE(...)`. Kit stores hide this; app modules use their dialect's package.
- Kit stores serve both dialects, so they use short constant SQL written once with `?` (`db.Rebind` numbers them for Postgres) and take `db.Transaction`, which any `db.Tx[S]` satisfies. App modules use Jet.
- `RETURNING` is Postgres-only; ids are made in Go, so read-after-write is rarely needed.
- Types through Jet on `database/sql`: typed ids bind with `id.Param()` on both engines (never Jet's `UUID(id)`, which binds the zero id as the all-zero uuid; `Param` binds the id itself, whose `Value` refuses the zero id) and scan into `ids.ID[T]` and `*ids.ID[T]` directly; an optional reference is a `*ids.ID[T]` (nil is NULL); `jsonb`/`json` columns are strings in models and scan into any type with a `Scan` method; `text[]` and `uuid[]` are `pq.StringArray`, and a `uuid[]` predicate needs a cast (`RawBool("refs @> #ids::uuid[]", ...)`); `xid8` is a string, bound with `CAST(String(x)).AS("xid8")`.
- Relations: load the parent page, then children with one `IN (...)` query and group in Go, or one join scanned into nested structs (Jet maps joined rows into `struct{ model.Invoices; Lines []model.InvoiceLines }`). Never a query per row.
- Escape hatch: a query Jet cannot express (rare: recursive CTEs it lacks, vendor functions) goes in the store as a constant SQL string with `?` or `$n` parameters and a comment saying why.
- `stmt.DebugSql()` is for tests and local debugging only; never log it in production (it inlines values).

## Pagination queries

Jet builds `ORDER BY` and keyset conditions at runtime, so one store function serves every allowed sort. `paging.Keyset` turns the verified cursor into the condition, in the right form for the dialect.

```go
var byID = paging.Key[model.Invoices]{Column: Invoices.ID, Value: func(r model.Invoices) any { return r.ID }}

var invoiceSorts = paging.Sorts[model.Invoices]{
    "issuedOn": {{Column: Invoices.IssuedOn, Value: func(r model.Invoices) any { return r.IssuedOn }}, byID},
    "number":   {{Column: Invoices.Number, Value: func(r model.Invoices) any { return r.Number }}, byID},
    "paidAt":   {{Column: Invoices.PaidAt, Value: func(r model.Invoices) any { return paging.Opt(r.PaidAt) }, Nullable: true}, byID},
}

func (s *Store) ListInvoices(ctx context.Context, tx db.Tx[db.Plain], f InvoiceFilter, p paging.Request) (paging.Page[Invoice], error) {
    where := Bool(true)
    if f.Status != nil {
        where = where.AND(Invoices.Status.EQ(String(*f.Status)))
    }
    sort, err := invoiceSorts.Resolve(p.Sort, "-issuedOn")
    if err != nil {
        return paging.Page[Invoice]{}, err
    }
    cond, err := s.keyset.After(p.Cursor, sort, f)   // verifies signature, sort and filter hash
    if err != nil {
        return paging.Page[Invoice]{}, err
    }
    stmt := SELECT(Invoices.AllColumns).
        FROM(Invoices).
        WHERE(where.AND(cond)).
        ORDER_BY(sort.OrderBy()...).
        LIMIT(int64(p.Limit + 1))
    var rows []model.Invoices
    if err := stmt.QueryContext(ctx, tx.Q(), &rows); err != nil {
        return paging.Page[Invoice]{}, err
    }
    return paging.Trim(rows, p.Limit, sort, f, s.keyset, toInvoice)
}
```

- Each sort key reads its value from the row through a typed accessor, so a joined row (`struct{ model.Invoices; Customer model.Customers }`) says exactly which `ID` it means. The cursor stores each value with its type (uuid, integer, bool, string, time, decimal) and binds it back as the same Go type; MySQL booleans bind as 0 or 1.
- Fetch `limit + 1` rows; the extra row only tells whether there is a next page.
- Every allowed sort has an index matching its column order and direction, with `tenant_id` first under tenancy: `(tenant_id, issued_on desc, id desc)`. No test checks it; review it with the migration.
- `paging.Keyset` renders `(a, id) < ($1, $2)` on Postgres and `a < ? OR (a = ? AND id < ?)` on MySQL, which does not use indexes well for row comparison.
- Nullable sort columns: the key sets `Nullable` (its value is `paging.Opt(ptr)`), sorts nulls last, and the cursor records whether the last value was null. Their keyset condition is an `OR` expansion on both engines, which indexes serve poorly; prefer not-null columns with a default when null has no meaning.
- Offset pages (numbered pages only) use the same sorts with `OFFSET`, capped by depth.
- Capped totals: `paging.CappedTotal(ctx, tx.Q(), SELECT(Invoices.ID).FROM(Invoices).WHERE(where), 10000)` counts over a `LIMIT 10001` subquery.

## Change feeds

Tables that feed sync clients carry a change position and keep tombstones.

<!-- part:postgres -->
Postgres (commit-safe):
- Column `change_xid xid8 not null default pg_current_xact_id()`, set again on every update (`change_xid = pg_current_xact_id()`), and an index `(tenant_id, change_xid, id)`.
- Deletes insert a row into `tombstones (tenant_id, entity, id, change_xid)` in the same transaction (`paging.Tombstone`); `deleted_at` is kept for pruning.
- Read `where (change_xid, id) > ($since_xid, $since_id) and change_xid < pg_snapshot_xmin(pg_current_snapshot()) order by change_xid, id limit $n`. Every transaction below the snapshot's xmin has finished, so no row can later appear behind the token.
- `paging.Feed` builds and verifies the token and merges rows with tombstones in order. The watermark is cluster-wide: any open transaction holds the feed back until it ends, which the timeouts bound.
<!-- /part:postgres -->

<!-- part:mysql -->
MySQL (lag window):
- `changed_at datetime(6)` set from the database clock (`now(6)`) on insert and update, plus the same tombstones table.
- Read only up to `now(6) - interval <lag>`, where the lag exceeds the longest allowed transaction (the lock and statement timeouts bound it). Weaker than the Postgres form; documented per app.
<!-- /part:mysql -->

Tombstones are pruned after the longest offline period the app supports (config); a client whose token is older than that is told to do a full sync (410 `resync_required`).

## Locking
- `db.Lock(ctx, tx, "<area>:<key>")` for serialising work that has no natural row to lock. Lock names are documented in the module that takes them. Take several in a fixed order. Names are exact (case and accents matter on both engines) and global across tenants; each name leaves one row in `locks`, so never build names from unbounded input. `Lock` writes, so it fails in a `ReadOnly()` transaction.
- Long work never holds a lock across network calls.

## Seed and setup
- `app setup`: production-safe, idempotent: creates missing built-in roles and keeps their permissions in step with their definitions; custom roles are never touched.
- `app db:seed`: local data (`APP_ENV=local` only): runs `setup`, then the administrator and, under tenancy, a tenant. A module that wants local data adds a step to `internal/app/seed.go`, deterministic (stable ids via `ids.Stable`), that checks one of its own rows before inserting, so it can fill a new module into an existing local database.
