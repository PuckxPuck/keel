# Kit packages

Everything under `internal/kit/`. Each package is app-agnostic: it takes configuration and registries from the app and never names a product concept. Signatures are abridged; the code is the authority.

Legend: **core** ships in every app; **optional** can be removed at `keel init`.

## Foundation

### config (core)
Parts the app embeds in its own `Config` struct and parses with one prefix.
```go
type Config struct {
    Env      config.Env  `env:"ENV,required,notEmpty"`
    HTTP     config.HTTP `envPrefix:"HTTP_"`
    Database db.Config   `envPrefix:"DATABASE_"`
    // ... the app's own fields
}
cfg, err := config.LoadFrom[Config]("APP_", os.Environ()) // parse, then Validate(prod) on every part, errors joined
```
`config.Secret` redacts itself in logs and `%v`; `config.Describe(prefix, cfg)` lists every setting with secrets redacted (`config:check`); `config.RequireStrong(name, secret, prod)` refuses a short (under 32 bytes) or example-valued secret in the production profile. Every field also reads `<NAME>_FILE`.

### logx (core)
`logx.New(cfg.Log, w, opts...) *slog.Logger` (JSON or text by `APP_LOG_FORMAT`), `logx.From(ctx)`, `logx.With(ctx, attrs...)` adds attributes for the rest of the request, a handler that copies request id, user id and client IP from the context into every record, and a redaction list for known sensitive keys. `logx.ContextAttrs(fn)` adds what `fn` finds in a record's context (otelx gives the trace and span ids).

### clock (core)
```go
type Clock interface{ Now() time.Time }
clock.Wall(ctx)        // real time; for expiry, leases, signatures
clock.Business(ctx)    // domain time; fixed or offset in tests and demos
clock.Today(ctx, loc)  // dates.Date in a location
clock.WithFixed(ctx, t), clock.WithOffset(ctx, d)
```
Domain code never calls `time.Now()`.

### ids (core)
`ids.New() uuid.UUID` (v7, panics only if the OS random source fails), `ids.Stable(namespace, name)` (v5, for deterministic seeds and imports). `ids.ID[T]` typed ids: `type InvoiceID = ids.ID[invoiceTag]`, `ids.NewOf[T]()`, `ids.Parse[T](s)`, JSON and SQL marshalling, `id.Param()` to bind it in Jet on either engine. The zero id is never stored: `Value` and `MarshalText` refuse it, `Scan` refuses the all-zero uuid in text and 16-byte form, and NULL scans to the zero id; optional references are `*ids.ID[T]`. Parse errors never echo the input.

### buildinfo (core)
`buildinfo.Get()` returns version, commit, build time, Go version; logged at startup, shown by `app about` and `doctor`, and the OpenAPI and OpenTelemetry version.

## HTTP

### httpx (core)
- `httpx.NewRouter() chi.Router` (not-found and method-not-allowed answer problem+json) and `httpx.NewAPI(router, opts) huma.API`, with `Options{Title, Version, BasePath, DocsEnabled, MaxBodyBytes, Realm, SpecPath}`. Operations are registered on the returned API and mounted under `BasePath`; docs, spec and schema routes exist only when `DocsEnabled`, except that `SpecPath` serves the document alone (`SpecPath.json`, `.yaml`) whatever `DocsEnabled` says (the public api realm).
- `httpx.Mirror(from, to, accept, adjust)`: every operation registered on `from` afterwards that `accept` takes is registered on `to` as well, with the same handler and options, recorded on `to`'s realm; `adjust` changes the copy's document entry. The api realm exposes the tenant realm's public operations this way.
- `httpx.Public(since, opts...)` (a `Register` option) marks an operation for the public api realm from `since` (a date, 2006-01-02); `httpx.Sunset(deprecatedOn, sunset)` retires it. `httpx.PublicOf(op)` and `httpx.IsPublic(op)` read the mark. The mark lives in core so core and module operations carry it whether or not the apikeys part is kept; without it the mark changes nothing.
- `problem.Install(mappers ...problem.Mapper)` (package `httpx/problem`): replaces Huma's error constructors once at startup, before any operation is registered (so the OpenAPI documents describe `Problem`; `keel gen` fails on Huma's `ErrorModel`); `internal/app` installs every kit part's mapper and the modules' in one place for `Build` and `Operations`. A mapper `func(error) (*problem.Problem, bool)` turns a domain error into a `Problem{Status, Code, Title, Detail, RequestID, Errors, Extensions}`. Huma validation errors become 422 `validation_failed` with `errors[]` rebuilt from fixed messages, so submitted values are never echoed; unmapped errors become 500 `internal`.
- Client address: `httpx.ClientAddress(ProxyConfig)` middleware, `httpx.ClientIP(ctx) netip.Addr`, `httpx.Proxied(ctx) bool`, `httpx.LocalProbe(ctx) bool` (a loopback client, or a trusted proxy on this host: how health probes arrive).
- Middleware: `RequestID`, `AccessLog` (route pattern, status, bytes, duration; health at debug), `Recover`, `SecurityHeaders(hsts)`, `CrossOrigin(trusted...)`, `CORS(allowlist)`, `MaxBody(n)`. `RequestID` and `ClientAddress` also add `request_id` and `client_ip` to the log context. `Recover` aborts the connection when a panic happens after the response started.
- `httpx.SafeReturnPath(raw) (string, bool)`, `httpx.NoStore`.
- `httpx.Serve(h)` (a `Register` option): after the API's and the operation's middleware, the request goes to the plain handler `h` instead of the operation's handler, with the path parameters as `r.PathValue`. Huma never reads the body, so `h` caps it itself, and a 2xx answer that is not JSON (a download) is exempt from the envelope check. The app mounts file uploads and downloads this way, so the realm's session, tenant guard, rate limits and `Need` run first.

### envelope (in httpx, core)
`httpx.One[T]`, `httpx.List[T]` (`Data []T` never null; `Meta ListMeta`; `Links`), `httpx.Feed[T]`, `httpx.NoContent`, and `httpx.Created[T]` (201, or 200 for a resource already stored; `Register` documents both); each wraps its payload in a `Body` field, built with `httpx.OneOf(v)`, `httpx.CreatedOf(v, created)` and `httpx.ListOf(items, meta, links)`. Operation outputs must be one of these; `httpx.CheckOutputs(api)` is the walk test's helper.

Operations register through `httpx.Register(api, op, handler, opts...)`, which applies options (`rbac.Need`, `ratelimit.Class`, `idempotency.Required()`; any `httpx.Option`), records the API's realm (`httpx.Options.Realm`, read back with `httpx.RealmOf(op)`) and applies the configured body cap (a body of exactly the cap is accepted; `httpx.BodyLimit(op)` reads it back); calling `huma.Register` directly is a lint error outside `kit/httpx`. `httpx.Operations(api)` lists every registered operation, hidden ones included (Huma leaves those out of the OpenAPI document), for the startup checks, walk tests and `route:list`; `httpx.Realm(ctx)` is the realm a request was routed to.

### health (core)
`health.New(checks ...health.Check)`, `(*Health).Mount(router)` for `/livez` and `/readyz` (checks cached 5 s, never run concurrently, no lock held while they run), `(*Health).Ready()` opens readiness once startup is done and `(*Health).Drain()` closes it before shutdown.

### server (core)
`server.Run(ctx, server.Options{...}, background ...func(ctx) error)` listens (TCP or `unix:/path`), runs background workers, and on cancel: `OnDrain` (readiness off), `DrainDelay`, `Shutdown` up to `ShutdownTimeout`, then stops the workers. `server.Serve` is the same on a listener you made.

### ratelimit (core)
```go
lim := ratelimit.New(ratelimit.NewMemory(cfg.Rate.MaxKeys))
for class, rule := range ratelimit.Defaults(cfg.Rate, principals) { lim.Define(class, rule) }
lim.Define("exports", ratelimit.Rule{Key: ratelimit.ByPrincipal(principals), Rate: rate})
httpx.Register(api, op, handler, rbac.Requires(p), ratelimit.Class(ratelimit.ClassAPIWrite))
api.UseMiddleware(lim.PreAuth(api, ratelimit.ClassPreAuth), lim.Middleware(api))
api.UseMiddleware(lim.Classes(api, pick))   // every class pick(ctx) names, in order (the api realm: api-key, api-tenant), each adding its headers
err = lim.Check(api)                        // startup: every operation has a defined class; lim.Defined(class)
store := ratelimit.NewDBStore(pool, dialect) // or ratelimit.DBStoreOf(d); security counters (D31): store.Take(ctx, key, rate) (the count comes back from the upsert), store.Reset(ctx, key), store.Refund(ctx, key, rate)
```
Key kinds: `ByAddress` (IPv6 /64), `ByNetwork` (/24 or /48), `ByPrincipal(principals)` (address when anonymous), `ByHeaderToken(header)` (SHA-256 of the value), `ByTenant` (the context's tenant, one bucket without tenancy; the `api-tenant` class), or a custom `KeyFunc`. `Rule{Key, Rate, Store, FailOpen, Skip}`: a class may use its own store; a failing store answers 503 on every path (`PreAuth`, `Middleware`, `HTTP`) unless `FailOpen`, which lets traffic through and logs; `Skip(ctx)` exempts requests (the default `health` class skips `httpx.LocalProbe`). An undefined class refuses at runtime too. Refusals are 429 `rate_limited` with `Retry-After` rounded up to whole seconds; answers carry `RateLimit-Policy` and `RateLimit` (IETF draft structured fields), one entry for each class that counted the request (`Classes`, then the operation's), on success as well as refusal; `PreAuth` adds them only when it refuses. `lim.HTTP(class)` covers plain routes (health). `DBStore` counts fixed windows in `rate_counters` with one upsert per hit on the pool, outside the request's transaction, with a 2 s timeout, retries a deadlock once and returns other errors, so security counters fail closed; `Prune(ctx, before)` clears old windows. Memory eviction looks at a sample of 64 buckets per shard.

## Data

### db (core)
```go
d, operator, err := db.Open(ctx, cfg.Database)               // dialect from the URL scheme; operator pool and capability when OPERATOR_URL is set; Postgres search path pinned to pg_catalog, public
err = db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { ... }, db.ReadOnly(), db.Retry(3))
// db.Tx[db.Tenant] on the same call needs the tenancy part's begin hook (db.OnBegin[db.Tenant]); without it InTx refuses
d, operator, err = db.Open(ctx, cfg.Database, db.ResetTenant(), db.Connector(otelx.OpenDB)) // options: the tenant reset (tenancy), and a pool made from the driver's connector (tracing)
err = db.InAppTx(ctx, d, func(ctx context.Context, tx db.Transaction) error { ... }) // tenant tx when ctx has a tenant, else plain
ctx = db.WithTenant(ctx, id); id, ok := db.TenantOf(ctx) // the tenant tenant transactions run as; kit/tenancy and the job worker set it
tx.Tenancy()                                                 // the schema carries tenant_id (tenancy hooks installed)
// tx.Q() is what Jet statements run against (qrm.DB: QueryContext and ExecContext; never the *sql.Tx); tx.Dialect()
err = db.InOperatorTx(ctx, operator, func(ctx context.Context, tx db.Tx[db.Operator]) error { ... }) // operator: from Open only (D29)
err = db.AfterCommit(ctx, func(ctx context.Context) { ... }) // ErrNoTx outside a transaction; runs even if ctx is cancelled after commit
db.BeforeCommit[db.Tenant](d, check)                         // runs last in every tenant transaction (D30); lint allows hooks only in kit/tenancy
err = db.Lock(ctx, tx, "invoices:number:2026") // with a tenant in ctx the name is prefixed with it
db.IsUniqueViolation(err), db.IsForeignKeyViolation(err), db.IsRetryable(err)
db.Insertable(Invoices.AllColumns) // insert columns minus tenant_id, change_xid, changed_at
db.NotFoundOr(err, ErrX)           // maps qrm.ErrNoRows to the module's not-found error
db.LikeEscape(q)                   // escapes % _ \ for LIKE and ILIKE
db.ErrCommitUncertain              // the connection failed during COMMIT; after-commit hooks did not run
db.HealthCheck(d)                  // health.Check pinging both pools
cfg.OperatorMaxOpen                // the operator pool's size (APP_DATABASE_OPERATOR_MAX_OPEN)
d, operator, err := db.Open(ctx, cfg, db.ResetTenant()) // tenancy: clear app.tenant_id on every checkout (one round trip)
```
`cfg.ValidateMigrate(prod)` checks only what migrations use (a target URL with verified TLS in production, the lock timeout); `cfg.VerifiesTLS()` says whether the database URL asks for a verified TLS connection. `InTx` retries serialization failures and deadlocks only (Postgres 40001 and 40P01, MySQL 1213; lock wait timeouts are not retried on either engine), default twice with jittered backoff; begin and before-commit hooks run on every attempt, and when retries run out the last attempt's error is returned. It rolls back on error or panic (and re-panics) and refuses a nested transaction. After-commit hooks run on a context detached from cancellation with a 30-second timeout. `Tx[Plain]`, `Tx[Tenant]` and `Tx[Operator]` do not convert into each other. `d.SQL()` (the raw pool) is for internal/kit, cmd and tests only; lint forbids it in internal/app and modules. `db.Dialect` (`Postgres`, `MySQL`) is available to kit code that needs it; app modules should not branch on it. Kit code that serves every scope takes `db.Transaction` (only a `db.Tx[S]` satisfies it) with `db.LockIn(ctx, tx, name)`, and writes its SQL once with `?` placeholders through `db.Rebind(dialect, query)`.

### migrate (core)
`migrate.New(pool, dialect, fsys, migrate.Options{Production})` wraps a goose provider with a session locker (Postgres advisory lock, MySQL `GET_LOCK`). Methods: `Up`, `Down` (refused in production and staging), `Status`, `Version`, `Current(ctx)` (startup schema check through the app pool: error when the database is behind, warning when ahead); `migrate.CheckCurrent(ctx, d, fsys)` runs it on a `*db.DB`. The MySQL lock name is hashed when `goose:` plus the database name passes MySQL's 64-character limit. `migrate.Validate(fsys, dialect, migrate.Allowed{Policies, Procedural})` checks file naming, Up and Down, one statement per Up and Down on MySQL (counted after goose's split and a SQL-aware split), exactly one Up statement in a `-- +goose NO TRANSACTION` file on either engine (a failure part way leaves at most one thing to clean up), refuses contract changes without `-- keel:contract` (D32), and on Postgres refuses a table given a `tenant_id` column without row-level security enabled, forced and a policy in the same file unless marked `-- keel:global`, and under tenancy refuses `DO` blocks and functions whose bodies run dynamic SQL or change tables, policies or row-level security unless the file says `-- keel:procedural <reason>` and `Allowed.Procedural` names it with that reason; `migrate.Without(fsys, modules...)` hides the named modules' migrations and `migrate.TenantModules(fsys, dialect)` names the modules with a migration that gives a table `tenant_id` (test templates without tenancy leave both out); see [conventions/database.md](conventions/database.md#migrations).

### testdb (core, test only)
`testdb.Main(m, testdb.Options{Migrations, RolePrefix, Template})` in `TestMain` gives the package a database per configured engine, cloned from a template migrated once per run; `testdb.Get(t) *db.DB` (first engine); `testdb.Each(t, func(t, e *testdb.Engine))` runs a contract test on every engine; `testdb.Isolated(t)` / `e.Isolated(t)` for a test that needs its own database; `e.Empty(t)` for an empty database connected as the owner, for migration tests; `e.Owner(t, d)` connects to the package or an isolated database as the role that runs migrations, for tests that act beyond the app's grants; `testdb.WithTemplate(name, version, prepare)` for seeded templates. Package databases leave out the tenancy migrations (`testdb.TenancyModule`) and every module whose migrations give a table `tenant_id` (module tables written in their final shape, D36); `testdb.Tenancy(t) *TenancyDB` gives a Postgres database with all of them (`DB` as the app role, `Operator` the operator capability through `db.Open`, `As(t, role)` for another role, `AsOperator(t, role)` for an operator pool as a `TempRole`, `AdminURL(t)` for commands that migrate it, `NewTenant(t, slug)` to add a tenant), and skips without Postgres. Engines come from `APP_TEST_DATABASE_URL` (Postgres; tests run as `<prefix>_app`) and `APP_TEST_MYSQL_URL`; `keel test` sets both for the compose defaults when reachable. On Postgres it resets the roles' attributes and revokes every membership of the app role on every run, and refuses to run tests when the app login is, or through any chain of memberships belongs to, a superuser, a role that bypasses row-level security, or the owner or operator role. On MySQL tests log in as a user made for the run (`<prefix>_t<hex>`, dropped at the end, or by a later run after a day) with what deploy grants the app user on each table (select, insert, update and delete; select and insert on `audit_log`); the admin URL only creates databases and migrates. Its databases are named `<prefix>_testdb_<stamp>_<hex>` and `<prefix>_testdb_tpl_<hash>_<stamp>`; the janitor drops only names that parse back into those shapes and are a day old. It reads the two variables itself, an accepted exception to kit code not reading env, since it only runs in tests.

### paging (core)
`paging.NewKeyset(dialect, keys...)` signs and verifies cursors (HMAC-SHA256, carrying the sort with its direction, a filter hash and the last row's sort values ending with the id; the first key signs, all verify); `paging.Sorts[R]` maps allowlisted `sort` values to `paging.Key[R]{Column, Value func(R) any, Nullable}` (typed accessors, no reflection; `paging.Opt(ptr)` for nullable values; nulls sort last); the cursor carries each value with its type and binds it back as the same Go type; `Sort.OrderBy()` and `Keyset.After(cursor, sort, filter)` build `ORDER BY` and the keyset condition (row comparison on Postgres, expanded `OR` on MySQL and for nullable sorts); `paging.Trim(rows, limit, sort, filter, keyset, conv)` turns `limit + 1` rows into a `paging.Page[T]{Items, Next}` and `page.List(limit, self)` into the list envelope with `links.next`; `paging.Offset{Page, Limit}.Skip(maxDepth)` (overflow-safe); `paging.CappedTotal(ctx, q, base, cap)`. Errors carry codes `cursor_invalid`, `cursor_mismatch`, `unknown_sort`, `page_too_deep`; `paging.Mapper` answers them with 400.

Change feeds: `f, err := paging.NewFeed(keyset, paging.FeedOptions{Entity, Retention, Lag})`; in a transaction `w, err := f.Open(ctx, tx, since, filter)` verifies the token (bound to the entity and filter hash; older than `Retention` is `paging.ErrResyncRequired`, 410 `resync_required` through `paging.Mapper`) and takes the watermark once; the store selects `WHERE w.Where(posCol, idCol) ORDER BY w.OrderBy(posCol, idCol)... LIMIT limit+1` (`change_xid` on Postgres, `changed_at` on MySQL); `paging.Changes(ctx, tx, w, rows, limit, change, conv)` merges the rows with the window's tombstones into a `paging.FeedPage[R]` whose `Body(limit)` is the `httpx.FeedBody`. Feed tokens are bound to the context's tenant. `paging.Tombstone(ctx, tx, entity, id)` in the deleting transaction; `paging.PruneTombstones(ctx, tx, now-Retention, limit)` for the retention job (call it in fresh transactions until it returns fewer than `limit`). `Lag` must exceed the longest transaction: a caught-up token's retention runs from `Lag` before it was made. A row deleted and recreated at the same position follows its tombstone.

### idempotency (core)
`idempotency.Middleware(api, idempotency.NewStore(d), cfg.Idempotency, principals)` on operations registered with `idempotency.Required()` makes them at most once:
- Keys belong to a signed-in principal in its realm (`(realm, principal, key)`; under tenancy the row's tenant joins the unique key). `idempotency.Prune(ctx, tx, before)` runs in the caller's transaction (the operator pool under tenancy). Anonymous callers get 401; `idempotency.Check(api)` (in the startup check) refuses a marked operation that is `Public` or has no body limit.
- The `Idempotency-Key` header is required (400 `idempotency_key_required`). The request hash covers method, route, path (so path parameters), the canonicalised query string, `Content-Type` and body; a repeat that differs is 422 `idempotency_mismatch`. Other headers are not covered.
- The claim is written in its own short transaction with a lease (`APP_IDEMPOTENCY_LEASE`, default 2 min). A repeat within the lease is 409 `idempotency_in_progress`; after it, until the key expires (`APP_IDEMPOTENCY_TTL`, default 24 h), 409 `idempotency_outcome_unknown`. A claim is never taken over.
- The response is buffered and its record saved before it is sent. Every answer below 500 is kept and replayed with `Idempotent-Replayed: true`, 4xx included (validation failures too: the corrected request has another hash, so it needs a new key either way). A 5xx or a failed save leaves the outcome unknown; the key is never released, so a retry cannot run the change twice. A body over `APP_IDEMPOTENCY_MAX_STORED_BYTES` (default 256 KiB) is sent whole but stored without its body; a repeat gets 409 `idempotency_response_not_stored` with `originalStatus`.
- Without a store, marked operations answer 503. `idempotency.Prune(ctx, d, before)` for the retention job.

### occ (core)
`occ.Check(ctx, result, load) error` after an `UPDATE ... WHERE id = ? AND version = ?` that bumps `version`: no row matched means `*occ.StaleError{Current{Version, ChangedBy, ChangedAt}}`, or whatever `load` returns when the row is gone; `occ.Mapper` answers 409 `stale_version` with `currentVersion`, `changedBy` and `changedAt`. `load` must be a locking read (`FOR UPDATE`): on MySQL a plain read returns the transaction's snapshot, which can predate the change that made the update miss.

## Identity and access

### auth (core)
```go
sess, err := auth.NewSessions(auth.Options{DB, Audit, Realms, Secure, CacheTTL, SecondFactor, Devices})
started, err := sess.Start(ctx, tx, userID, auth.Meta{Kind: auth.KindBrowser, Provider: "password"}) // rotates, audits
// auth.Meta{SecondFactorPassed: true} starts past the realm's MFA (a passkey sign-in with user verification)
started, err := sess.PassMFA(ctx, tx, "totp")   // rotates a restricted session into a passed one
sess.End(ctx, tx); sess.RevokeUser(ctx, tx, userID); sess.RevokeOthers(ctx, tx, userID, keepSessionID)
api.UseMiddleware(sess.Resolve(), limiter, sess.Require(api, principals), rbac.Enforce(api, principals), sess.Restrict(api))
auth.SessionFrom(ctx) (Session, bool); auth.PrincipalFrom(ctx) (rbac.Principal, bool)
auth.AllowWhileRestricted(), auth.RecentMFA(within)   // httpx.Register options
f := auth.NewFailures(ratelimit.DBStoreOf(d)); f.Attempt(ctx, limits...); f.Succeeded(ctx, limits...); f.Fail(ctx, limit)
```
- Sessions table: token is 32 bytes from `crypto/rand`, base64url to the client, SHA-256 stored (`auth.NewSecret`, `auth.HashSecret`). Kinds `browser` (cookie only), `api` (bearer only) and `device` (resolved from `devices`, no session row). `mfa_state` is `none`, `pending` or `passed`, with `mfa_at` for step-up.
- Cookie per realm: the realm's `Cookie` name, `__Host-` prefixed and `Secure` when `Secure` (production), `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`, expiring with the session's absolute expiry. Bearer tokens come only from `Authorization: Bearer`, never a cookie or query string.
- `Start` refuses with `auth.ErrNoAccess` a user who holds no role in the realm (callers answer it like bad credentials), deletes whatever session the request's token named, opens one in the request's realm (pending when the realm requires MFA, or when it is optional and the user has a confirmed factor; a pending session lives `auth.PendingFor`, ten minutes), records the user's access version on it, audits `session.start` as the user, and sets the cookie once the transaction commits.
- `Resolve` never refuses: a missing, malformed, expired, revoked, other-realm or wrong-kind token leaves the request anonymous (and clears a stale cookie). Touch is at most once a minute and never extends past the absolute expiry. The session row is read with the user's `access_version` (`users.BumpAccess` moves it on every grant, revocation, role permission change or deletion, status change and password change, in the change's transaction). When it differs from the session's, a browser session rotates (new cookie, old token dead) and a bearer session records the new version. Principals are cached by user, realm and version (5 s by default), so a change applies on the next request on every replica. A pending session's principal carries the user and no grants. Device resolver errors other than `auth.ErrInvalidToken` are logged. Through `rbac.WithHook(sessions)` a user left with no role in a realm loses their sessions there.
- `Require` answers 401 `session_expired` for an expired or revoked session on a non-public operation; `Enforce` answers other signed-out callers. `Restrict` answers 403 `mfa_required` to a restricted session outside `AllowWhileRestricted` operations, and 403 `mfa_step_up_required` when `RecentMFA(within)` is not met (devices never meet it).
- `Failures` counts attempts at secret checks in `rate_counters`: `Attempt` takes every counter before the check (the upsert returns the count, so a concurrent burst cannot pass) and refuses with `*ThrottledError` (429 with `Retry-After`) over a limit; `Succeeded` clears the counters marked `Reset` (an account's) and refunds the others; `Fail` counts a consecutive failure and reports when it reached its limit. Keys from `auth.Key(kind, parts...)` hash their parts; `auth.Address(ctx)` says whether the client address is known, so address-paired keys are skipped rather than shared.
- `auth.Prune(ctx, tx, before)` deletes sessions past their absolute expiry or revoked before `before`.

Realms (`kit/auth/realm`): `realm.New(httpx.Options, realm.Realm{Name, Hosts, BasePath, SpecPath, Catalogue, Cookie, Idle, Absolute, MFA, Loader}...)` builds one router, Huma API and OpenAPI document per realm and is the `http.Handler` that picks the realm by host (exact, ignoring port, case and one trailing dot; internationalised names match their punycode; a realm without hosts takes unclaimed hosts; otherwise 404 problem+json). The Host is parsed as `net.SplitHostPort` does: brackets only around an IPv6 literal and a numeric port, else 400. Realms may not share a cookie name. `set.API(name)`, `set.Realm(name)`, `set.Each(fn)`, `set.For(host)` (the realm a Host header routes to; the app skips CSRF and CORS for the api realm with it). The realm name reaches handlers, logs and audit through `httpx.Realm(ctx)`.

### auth/tokens (core)
`tokens.Issue(ctx, tx, userID, tokens.PasswordReset, ttl) (raw string, err)` upserts the one row per user and purpose, so only the latest link works even when two are issued at once; `tokens.Consume(ctx, tx, raw, purpose) (userID, err)` spends it in the caller's transaction (single use, hashed, purpose-bound; a wrong purpose does not spend it; the spend must change exactly one unused row); every refusal is `tokens.ErrInvalid` (422 `invalid_token`). `tokens.Notifier` (`SendReset`, `SendVerify`, `SendInvite`, each `(ctx, tx, user, token)`) is called inside the issuing transaction and must only enqueue (a mail job in `tx`), never do network I/O; an error rolls the change back. `tokens.LogNotifier{}` logs links after commit, for `APP_ENV=local` only. `tokens.Prune`.

### auth/totp (core, off per realm until enabled)
`totp.New(keys, issuer, rec)`, `svc.Enrol(ctx, tx, user) (Enrolment{Secret, URI})`, `svc.Confirm(ctx, tx, userID, code) (recoveryCodes, err)`, `svc.Verify(ctx, tx, userID, code)` (one step of skew, each step once), `svc.RecoveryCodes(ctx, tx, userID)` (replaces them, shown once), `svc.UseRecovery`, `svc.Enrolled` (an `auth.SecondFactor`). Secrets are sealed with AES-256-GCM under a key derived (HKDF-SHA256) from the newest `APP_MFA_KEYS` entry, bound to the user; any listed key opens them and a secret opened with an older key is resealed on use.

<!-- part:passkey -->
### auth/passkey (optional)
```go
svc, err := passkey.New(passkey.Options{Config: cfg.Passkey, DisplayName, Tx, Audit})
c, err := svc.BeginRegistration(ctx, tx, user)                                   // Challenge{ID, Options} for navigator.credentials.create
p, err := svc.FinishRegistration(ctx, userID, c.ID, response, name, then)         // then runs in the storing transaction
c, err := svc.BeginSignIn(ctx, tx)                                                // discoverable, user verification required
err = svc.FinishSignIn(ctx, c.ID, response, func(ctx, tx, userID) error { ... }) // start the session in the same transaction
list, err := passkey.List(ctx, tx, userID, limit)                                 // the user's passkeys on the request's realm
p, err := svc.Rename(ctx, tx, userID, id, version, name)                          // occ.StaleError on a stale version
err = svc.Remove(ctx, tx, userID, id, func(ctx, tx, kept int) error { ... })      // allow may refuse (ErrLastFactor)
passkey.Prune(ctx, tx, before)
```
WebAuthn through go-webauthn (pre-1.0, pinned). Credentials in `passkeys` (realm, credential id, public key, sign count, transports, AAGUID, flags, name, version, last used); a passkey records the realm it was registered on (`httpx.Realm(ctx)`) and signs in only there, and `List`, `Rename` and `Remove` see only the user's passkeys on the request's realm (anything else is `ErrNotFound`, 404). `Remove` locks the user's passkeys on the realm, so two removals cannot each count the other as kept, and records `passkey.removed`; challenges in `auth_challenges`, five minutes, spent in their own transaction before the answer is verified, so a failed ceremony cannot retry with one. Registration asks for a resident key and user verification and excludes the user's passkeys. A sign-in whose sign count did not move forward is logged and refused (`ErrInvalid`); since the sign-in verified the user, the app starts the session with `auth.Meta{SecondFactorPassed: true}`. `Config{RPID, Origins}` (`APP_PASSKEY_RP_ID`, `APP_PASSKEY_ORIGINS`): origins exact and on the relying party id, `https` (plain `http` only for `localhost` outside production).
<!-- /part:passkey -->

### auth/devices (core)
`devices.New(rec, grants)`, `svc.NewPairingCode(ctx, tx, actor, realm, name, scope)` (8 Crockford base32 characters shown as `XXXX-XXXX`, single use, 10 minutes; the caller's operation decides who may), `svc.Pair(ctx, tx, realm, code) (token "device_id.secret", Device, err)` (a code made for another realm is invalid), `svc.Rotate(ctx, tx, realm, id, grace)` (grace clamped to 0 to `devices.MaxGrace`, 24 h), `svc.Revoke(ctx, tx, realm, id)`, `devices.List(ctx, tx, realm, after, sort, limit)` with `devices.Sorts` for `paging.Trim`, `devices.ParseID`, `svc.ResolveDevice` (an `auth.DeviceResolver`: the session resolver's bearer path for tokens with a dot), `devices.Parse(raw)` (fuzzed). The scope is opaque; `grants(realm, scope)` turns it into the device principal's grants (`rbac.NewSubject(rbac.SubjectDevice, ...)`).

### auth/password (core)
`password.NewHasher(params, maxConcurrent)`: `Hash`, `Verify(ctx, encoded, plain) (ok, rehash, err)` (argon2id PHC strings with bounded parameters, or legacy bcrypt up to cost 15), `NeedsRehash`, `DummyHash`; a slot wait of one second then `ErrBusy` (429). `password.NewService(hasher, failures, throttle, rec)`: `Authenticate(ctx, d, email, plain, then)` counts the attempt first, reads the user and hash in a short read-only transaction, verifies with no connection held, and runs the rehash and `then` (start the session) in one closing write transaction; every failure (unknown, disabled or passwordless account, wrong or over-long password, legacy or out-of-bounds hash) runs one argon2id verification at configured cost and is `ErrInvalidCredentials`. `Prepare(ctx, plain, policy) (Hashed, error)` checks and hashes before a transaction opens; `Set(ctx, tx, userID, hashed)` stores it and moves the user's access version. Passwords are NFKC-normalised before hashing; bcrypt tries the raw input first. Stored argon2id parameters are bounded relative to the configured ones (`ErrOutOfBounds`). `password.Policy{MinLength}.Check` (NIST length on the normalised form, `MaxChars` 128 and `MaxBytes` 512, embedded common list, no composition rules); `Config.Policy(mfaRequired)`; `Config` refuses memory times max concurrent over `MemoryBudget`. Hashes live in `credentials`.

<!-- part:tenancy -->
### tenancy (optional, Postgres only)
```go
svc, err := tenancy.New(tenancy.Options{DB, Config, Audit, Realm, Catalogue, Templates, Owner, AllowReadOnly, AllowNonMember, ReservedHosts}) // installs the tenant transaction hooks
api.UseMiddleware(svc.Resolve(api) /* before the session */, sessions.Resolve(), svc.Guard(api, principals) /* before Enforce */)
t, err := svc.Create(ctx, operatorTx, tenancy.NewTenant{Slug, Name, Owner, Domains}) // tenant, owner membership, roles from the templates
t, err = svc.SetState(ctx, operatorTx, id, tenancy.ReadOnly, reason)                 // audited; suspending ends the tenant's sessions
t, err = svc.Enter(ctx, tx, id, user)                                                // may the user switch there
ctx = tenancy.WithTenant(ctx, t); t, ok := tenancy.FromContext(ctx)
run := tenancy.Runner(d)                           // tenant tx for job handlers and kit services; ErrNoTenant without a tenant, never another pool
global := tenancy.OperatorRunner(operator)          // operator tx for global kinds and sweeps; only internal/app holds operator
err = tenancy.CheckCatalogue(ctx, tx, exceptions...) // the schema rules of tenancy.md section 4
err = tenancy.CheckRoles(ctx, d, operator)          // startup: no app role that escapes row-level security, by attribute or membership; an operator login with bypassrls and nothing more
tenancy.AllowWhileReadOnly()                        // httpx.Register option
```
`Service` is also the `auth.Tenancy` of the sessions (`Admit` picks the tenant a sign-in lands in and checks membership). Store functions: `Get`, `BySlug`, `ByDomain`, `List` (operator), `Memberships`, `IsMember`, and on a `db.Tx[db.Operator]` only `AddMember` and `RemoveMember` (which also takes the removed member's sessions out of the tenant). `tenancy.HostTenant(ctx)` is the tenant the request's host named, even after the context's tenant changed (a signed file link). `KitExceptions` is the global allowlist and the excepted indexes, policies and functions; `tenancy.Exception{Table, Index, Policy, Nullable, Function, BodySHA256, Reason}` (a function by schema-qualified signature with the SHA-256 of its body). `KitProcedural` are the kit's migrations allowed to run procedural SQL under tenancy (`migrate.Procedural`). Errors map to 403 `not_a_member`, `tenant_read_only`, `tenant_suspended` and 404 `tenant_not_found` (`tenancy.Mapper`). Design in [tenancy.md](tenancy.md).
<!-- /part:tenancy -->

<!-- part:oidc -->
### auth/oidc (optional)
```go
svc, err := oidc.New(oidc.Options{Config: cfg.OIDC, Realms, RedirectURL, Tx: oauthstate.PlainTx(d), Audit, Corroborate, Secure})
started, err := svc.Start(ctx, returnTo)                     // provider URL, and the cookie binding the state to this browser
svc.Enabled(realm)                                            // OIDC works on the realms in Options.Realms only
claims, returnTo, err := svc.Finish(ctx, state, bound, code) // state spent first, then exchange (PKCE) and ID token checks
userID, err := svc.Link(ctx, tx, claims)                      // then sessions.Start in the same transaction
```
Discovery happens on first use, not at startup, and never inside a transaction: `Start` discovers first and then opens its own short transaction for the state, `Finish` discovers before it spends the state, and the token exchange and key fetch run with no transaction open. A failed discovery answers every sign-in with `ErrUnavailable` for 30 seconds before the provider is asked again. The ID token is verified with the provider's verifier, so the signing algorithms it advertises (ES256, PS256 and so on) are accepted. State, nonce (hashed) and PKCE verifier live in `oauth_states` through `kit/oauthstate`; the state is also set in an `oidc_state` cookie (`__Host-` in production, ten minutes) and must match it, so a callback URL cannot be replayed into another browser. The ID token is checked for issuer, audience (and `azp` with several audiences), expiry, issue time (at most five minutes ahead, ten minutes old) and nonce. `Link` signs in the user an `identities` row (realm, provider = issuer, subject) names on the request's realm; otherwise it links the existing active user holding the claimed address when the `Corroborator` agrees, and the default `VerifiedEmail{Trusted: APP_OIDC_EMAIL_TRUSTED}` agrees only for a trusted provider and `email_verified`. A user who already has an identity from the same provider under another subject is refused (an address the provider reassigned to someone new does not reach the old account; a changed subject needs the app's Corroborator or an operator). Two first sign-ins of one subject at once both sign in: the second waits for the first link and follows it. It never creates users. Errors: `ErrInvalidState` 400, `ErrToken` 401, `ErrRefused` 403, `ErrNotEnabled` 404, `ErrUnavailable` 503.
<!-- /part:oidc -->

### oauthstate (core helper)
`oauthstate.Put(ctx, tx, oauthstate.New{Purpose, Provider, ReturnTo, UserID, Nonce, TTL}) (Started{State, Verifier, Nonce}, error)`, `oauthstate.Take(ctx, tx, state, purpose, provider) (Taken, error)` (deletes the row whatever the answer; commit on `ErrInvalid` too), `taken.NonceMatches(nonce)`, `oauthstate.Prune(ctx, tx, before)`, `oauthstate.PlainTx(d)`. The shared store of `oauth_states`: the state is kept as SHA-256, the nonce as its SHA-256, the PKCE verifier as is (the token request needs it).

### auth/devlogin (core, local only)
`devlogin.Gate(env, enabled, listenAddr)` refuses it outside local or off loopback (config validation); `devlogin.Middleware` (an operation middleware on the dev login operation) is the per-request gate: a loopback client, not proxied, a loopback Host, and no forwarding header. `devlogin.Allowed(ctx)` reads its verdict (false when it did not run). The operation answers 404 when either says no.

### rbac (core)
```go
cat := rbac.NewCatalogue(rbac.Perm{Code: "notes.read", Area: "Notes", Label: "...", Sensitive: false, APIGrantable: true}, ...)
p := rbac.NewPrincipal(userID, realm, grants...); p.Can(perm), p.CanIn(perm, scope), p.Missing(perms...), p.Permissions()
p := rbac.NewSubject(rbac.SubjectDevice, deviceID, realm, grants...); p.Kind(), p.Subject(), p.Key(), p.ActingFor(user), p.OnBehalfOf()
rbac.Requires(perms...), rbac.RequiresAny(perms...), rbac.SignedIn(), rbac.Public() // httpx.Register options
rbac.RequiresIn(perm, rbac.PathScope("branch", "id"))  // perm everywhere, or within the scope the request names
api.UseMiddleware(rbac.Enforce(api, principals)) // 401 signed out, 403 unmet, before the handler
err = rbac.Check(api, cat)                       // startup: every operation, hidden too, has a Need from the catalogue
p, err := rbac.NewLoader(realm, cat).Load(ctx, tx, userID)
access := rbac.NewAccess(recorder, rbac.Policy{AccessManage: code}, map[string]*rbac.Catalogue{realm: cat}, rbac.WithHook(sessions))
access.Setup(ctx, tx, realm, builtins)
access.Grant(ctx, tx, actor, rbac.UserRole{UserID, RoleID, Scope}); access.Revoke(ctx, tx, actor, userRole)
access.SetRolePermissions(ctx, tx, actor, roleID, version, perms) (Role, error); access.DeleteRole(ctx, tx, actor, roleID, version)
access.CreateRole(ctx, tx, actor, rbac.NewRole{Code, Name, CopyFrom, Permissions}) (Role, error)
access.Sync(ctx, tx, realm, builtins)            // existing built-in roles carry exactly their definitions' permissions (app setup)
rbac.Holders(ctx, tx, realm, perm)               // active users holding perm everywhere: who to mail about their area
rbac.RolesOf(ctx, tx, realm, userID), rbac.HoldsAnyRole(ctx, tx, realm, userID)
rbac.System(realm)                               // break-glass actor for shell commands (user:grant)
```
`rbac.Principals` is the small interface `Enforce` reads the caller through; `rbac.FromContext{}` reads what `rbac.WithPrincipal(ctx, p)` stored (the session resolver sets it). `Requires` and `RequiresAny` pass only on grants held everywhere; a scoped grant counts only through `RequiresIn`, whose scope comes from the request, and services still call `CanIn` for targets the request does not name. The system principal never passes `Enforce`.

`Access` is the only writer of roles and grants, and the guard `users.Service` needs (`CheckStatus`). Each change takes `db.Lock("rbac:access:<realm>")`, loads the role and the facts the rules need with locking reads inside the transaction, checks the acting principal, writes and audits; callers never supply facts. Rules: the actor holds the access-management permission where the change applies (else `ErrForbidden`, 403); nobody changes their own grants; nobody grants a role carrying, or adds to a role, a permission they do not hold there; a realm keeps at least one active user holding access management everywhere (scoped grants and disabled users do not count) and at least one role carrying it; roles of another realm are `ErrRoleNotFound`. Violations come back together as `*RefusedError`; `rbac.Mapper` answers 422 `checks_failed` with `checks[]` and maps not found (404), already granted (409), forbidden (403) and a change to a built-in role (422 `builtin_role`). `rbac.System(realm)` skips the checks of what the actor holds, never the realm check or the last-holder rules. Unknown codes in the database are skipped with a warning. Built-in roles belong to the code: `SetRolePermissions` and `DeleteRole` refuse them with `ErrBuiltinRole`; `Setup` creates missing ones and `Sync` makes each existing one carry exactly its definition's permissions (adding and removing), records `role.permissions_synced` and moves the holders' access versions. A role meant to lack a permission is a custom role.

### audit (core)
`rec := audit.New(audit.Options{Chain})`, `rec.Record(ctx, tx, audit.Event{Action, Entity, EntityID, Before, After})` in the caller's transaction (`tx` is any `db.Tx[S]`); the actor (`audit.WithActor`, the system when unset), realm, client IP and request id come from the context. Before and after images are walked structurally: struct fields tagged `audit:"redact"` are written as `[redacted]` and `audit:"-"` are dropped even when the struct has its own `MarshalJSON`; other types with their own JSON or text marshalling are written as `[opaque]` unless they implement `audit.Redactable` (`AuditValue() any`) or are known safe (`time.Time`, `uuid.UUID`, `ids.ID`, `dates.Date`, `money.Amount`, `config.Secret`); map keys are stringified, and keys `logx` treats as sensitive are redacted. Images are canonical JSON with sorted keys and every number in positional notation (`1e21` is written `1000000000000000000000`), so they read back identically from jsonb and MySQL json. Integers in the 64-bit range are hashed exactly; other numbers are doubles in MySQL json (and MySQL 8.4 can store a bound double one unit off), so they are hashed at 15 significant digits and a change past that is not detected. Marshal values that need more digits as strings. With `Chain`, each row stores the previous row's hash and its own (SHA-256 over that and the row's canonical JSON); the chain's head row in `audit_chain` (key `global`; one per tenant with tenancy) is read with a locking read and moved in the same transaction, so the chain cannot fork on either engine or isolation level. Under tenancy rows carry `tenant_id`, the context's or `Event.Tenant` (an operator acting on a tenant), and each tenant chains on its own head (key: the tenant id). `audit.Verify(ctx, tx) (Report, error)` walks one chain (the whole log without tenancy; the context's tenant's, or the rows without a tenant, under it), reports every break (not only the first) and counts unchained rows, and checks the last chained row is the one the head names (a deleted tail). The chain has no key: whoever can write `audit_log` and `audit_chain` directly can recompute it, so keep a copy of the head's hash outside the database if that matters. `audit.List(ctx, tx, before, limit)` reads entries newest first (the context's tenant's under tenancy, so the operator pool reads one tenant's trail). The app role may only insert and select `audit_log` (its migration on Postgres; on MySQL an operator grant that `app doctor` checks, P6).

### users (core)
`users.NewService(rec, guard).Create(ctx, tx, users.NewUser{Email, Name})` (email trimmed, lower-cased and NFC-normalised, then compared exactly on both engines: `JOSE@x` is `jose@x`, `josé@x` is another address; audited), `SetStatus(ctx, tx, actor, id, version, status)` (the guard, `rbac.Access` in apps, runs first and refuses disabling the last access manager; optimistic with `updated_by` as the 409's `changedBy`; audited), `users.Get`, `users.ByEmail`, `users.MarkEmailVerified` (sets `emailVerifiedAt` once), `users.BumpAccess(ctx, tx, ids...)` and `users.AccessVersion(ctx, tx, id)` (the version sessions compare; `SetStatus` and `rbac.Access` move it), `users.Mapper`. `users.Actor` is anything with `ActingUser() (users.ID, bool)`; `rbac.Principal` is one (a device or key acts as the user it is on behalf of, if any). Sign-in data lives in auth tables (`credentials`, `sessions`, `mfa_totp`).

<!-- part:apikeys -->
### apikeys (optional)
```go
svc, err := apikeys.New(apikeys.Options{Format: apikeys.Format{Prefix, Env}, Realm: "api", Catalogue, Manage, Audit, OnLeak})
plain, key, err := svc.Create(ctx, tx, actor, apikeys.NewKey{Name, Scopes, ExpiresAt, AllowedCIDRs, RateClass}) // plaintext once
err = svc.Revoke(ctx, tx, actor, id); apikeys.List(ctx, tx, before, limit); apikeys.Get(ctx, tx, id)
resolved, err := svc.Resolve(ctx, tx, raw, clientIP)   // Resolved{Key, Principal}; every refusal is ErrInvalidKey
api.UseMiddleware(svc.Middleware(api, apikeys.NoTenancy{}, run), apikeys.Lifecycle) // run(ctx, tenant, fn) opens the key's transaction; Lifecycle sends Deprecation and Sunset
apikeys.Document(public); httpx.Mirror(tenant, public, httpx.IsPublic, apikeys.Expose) // the api realm's document and its copies of the httpx.Public operations
err = apikeys.Check(public, now)                                                       // every api operation marked, dated, with enough notice
id, secretHash, err := svc.Format().Parse(raw)                                        // shape and checksum, no database; fuzzed
replayed, err := verifier.Seen(ctx, tx, deliveryID)                                   // same transaction
results, err := svc.ReportLeaks(ctx, tx, reports, replayed)                           // label, and revoke unless replayed
keys, err := apikeys.DueForReminder(ctx, tx, within); apikeys.MarkReminded(ctx, tx, id)
err = apikeys.Check(api, now)                                                         // startup check of the api realm
apikeys.Document(api)                                                                 // the api realm's bearer scheme; Expose attaches it
```
`Create` checks the actor holds `Manage` and every scope, and that each scope is in the catalogue and `APIGrantable` (`rbac.RefusedError` with `unknown_permission`, `not_api_grantable`, `grant_exceeds_actor`; the system actor skips only the last). `Resolve` reads the row on every request (D34), compares the secret's SHA-256 in constant time, applies revocation, expiry and the CIDR allowlist, writes `last_used_at` and `last_used_ip` at most once a minute and never waits for it (the row is taken `FOR UPDATE SKIP LOCKED`; when another transaction holds it the write is skipped), and returns `rbac.NewSubject(rbac.SubjectAPIKey, keyID, realm, scopes...)` with only scopes still grantable. The middleware takes `Authorization: Bearer` only, answers 401 `invalid_api_key` (with `WWW-Authenticate`) to a key that does not check out, and sets the principal, the `apikey` audit actor and `apikeys.FromContext`. It checks a key in two steps: a `Locator` finds the key's `Tenant` from its id alone (`NoTenancy` without tenancy), then the `TxRunner` opens that tenant's transaction for `Resolve` (the P4 seam, [tenancy.md](tenancy.md)). `ReportLeaks` revokes with a conditional update, so only the report that revokes a key records `apikey.leaked` and runs `OnLeak`; a report of a key already revoked records `apikey.leak_reported` and runs nothing, and a replayed delivery (`replayed`) only answers. `Check` refuses a `Sunset` whose deprecation date is still to come: add it in the release that deprecates. Format and table in [integrations.md](integrations.md#1-api-keys).
<!-- /part:apikeys -->

<!-- part:webhooks -->
### webhooks (optional, outbound)
```go
keys, err := seal.NewKeyring(cfg.WebhooksOut.Keys /* or connection keys */, "webhooks")
svc, err := webhooks.New(webhooks.Options{Queue: q, Tx: jobs.PlainTx(d), Keys: keys, Config: cfg.WebhooksOut, Audit: rec, OnDisabled: notifyAdmins})
ep, secret, err := svc.CreateEndpoint(ctx, tx, webhooks.NewEndpoint{URL, Description, Events})   // secret shown once
svc.RotateSecret(ctx, tx, id, version), svc.EnableEndpoint, svc.DisableEndpoint, svc.DeleteEndpoint  // same arguments; audited when Audit is set
// after RotateSecret the old secret signs beside the new one for Config.SecretOverlap (APP_WEBHOOKS_OUT_SECRET_OVERLAP)
svc.Endpoint, svc.Endpoints
id, err := svc.Emit(ctx, tx, "order.paid", payload)                                             // in the causing transaction
svc.Replay(ctx, tx, deliveryID), svc.Deliveries(ctx, tx, limit), svc.Rekey(ctx), webhooks.Commands(open)  // webhook:deliveries, webhook:replay, webhook:rekey
// Replay queues the new delivery and its job for the original delivery's tenant, also in an operator transaction
```
- Emit records the event and one `webhook_out_deliveries` row and `webhooks.deliver` job per active subscribed endpoint (`*` subscribes to everything). Bodies are `{type, timestamp, data}`, signed with Standard Webhooks headers; `webhook-id` is the event id, so a replay is recognisable. Endpoint secrets are sealed with AES-GCM (`kit/seal`), bound to the endpoint id.
- Retries at 5 s, 1 m, 5 m, 30 m, 2 h, 6 h, 12 h, 24 h, 24 h (ten attempts, about three days). Any 2xx resets the endpoint's consecutive failure count; a delivery that spends its last attempt disables the endpoint when the count has reached `APP_WEBHOOKS_OUT_DISABLE_AFTER`, and `OnDisabled` runs in that transaction. Deliveries to a disabled endpoint are skipped. `webhooks.prune` deletes events and their deliveries after `APP_WEBHOOKS_OUT_RETAIN`.
- Endpoint changes take the version the caller read; a stale one is `*occ.StaleError` (409 `stale_version`).
- Each delivery row carries a generation, the job attempt that wrote it; an outcome is recorded only when its generation is newer than the stored one, and only that write moves the endpoint's failure count or disables it, so a worker that lost its lease cannot overwrite the run that replaced it. An attempt cut short by shutdown or a lost lease records nothing and does not spend the attempt. A secret no key opens, or an `http://` URL once `APP_WEBHOOKS_OUT_ALLOW_HTTP` is off, fails the delivery for good (codes `secret`, `insecure_url`). A secret opened with an older key is resealed with the newest on delivery; `Rekey` reseals the rest.
- The client: `https` only unless `APP_WEBHOOKS_OUT_ALLOW_HTTP` (refused in production); a `kit/netguard` client (below); `APP_WEBHOOKS_OUT_TIMEOUT`; at most 64 KiB of the response is read.
<!-- /part:webhooks -->

### netguard (core helper)
```go
client := netguard.NewDialer(timeout).Client(timeout)       // no proxy, no redirects; Transport(timeout) for a custom client
netguard.Allowed(addr), netguard.HostAllowed(host), netguard.ErrBlocked
netguard.NewDialer(timeout, netguard.Permit(prefix), netguard.Lookup(fn))  // tests: admit a loopback server, fake DNS
```
- Default deny: an address is allowed only if it is public IPv4 unicast outside every IANA IPv4 special-purpose block that is not globally reachable, or IPv6 inside `2000::/3` outside every such IPv6 block. `2002::/16` (6to4), `2001::/32` (Teredo), `64:ff9b::/96` and `64:ff9b:1::/48` (NAT64) and `168.63.129.16` (Azure WireServer) are refused outright, and a block is refused whole even where IANA lists a reachable entry inside it. IPv4-mapped and IPv4-compatible IPv6 are judged as the IPv4 they carry. Any address with a zone, and a `%` in a host, is refused.
- The dialer resolves once, refuses the host if any address is not allowed, connects only to a checked address and checks the dialled address again in the socket's `Control`, so DNS rebinding cannot move it.

<!-- part:connections -->
### connections (optional)
```go
keys, err := seal.NewKeyring(cfg.Connection.Keys, "connections")
svc, err := connections.New(connections.Options{Tx: connections.PlainTx(d), Keys: keys, Providers: []connections.Provider{acme}, HTTPClient: c})
authURL, err := svc.Start(ctx, tx, "acme", userID, returnTo)       // single-use state with a PKCE verifier in oauth_states
conn, returnTo, err := svc.Finish(ctx, "acme", userID, state, code) // state spent first, then exchange, identify, store
client := svc.Client(conn.ID)                                        // *http.Client for the provider's API origins
err = svc.Disconnect(ctx, conn.ID); svc.Get(ctx, tx, id); connections.PruneStates(ctx, tx, before)
svc.Rekey(ctx), connections.Commands(open)                           // connection:rekey
```
- `connections.Config` (`APP_CONNECTION_KEYS`) may be empty; the app then runs no connections (`New` needs a keyring).
- `Provider` (app side): `Name`, `OAuth2() *oauth2.Config`, `APIOrigins()` (`https://host[:port]`; `http` only on loopback, for tests), `Account(ctx, client)` (the external account id and scopes), `Revoke(ctx, client, token)` or `ErrRevokeUnsupported`. A provider that also implements `AuthOptioner` adds authorisation URL options (`oauth2.AccessTypeOffline` for Google).
- The state lives in `oauth_states` through `kit/oauthstate`, bound to the user who started, ten minutes by default, and spent even when it is refused. Reconnecting the same external account replaces its tokens; two first connects at once end as one row.
- The default HTTP client is a `kit/netguard` client (30 s). The API client sends the token only to the provider's origins (`ErrOriginNotAllowed` otherwise) and follows a redirect only within the same origin. Provider failures cross the package boundary only as `ErrProviderUnavailable` (network, timeout, 429, 5xx) or `ErrProviderFailed`, with the operation and at most an RFC 6749 error code or HTTP status; bodies, headers and adapter messages are dropped.
- Access and refresh tokens are sealed with AES-256-GCM under keys derived from `APP_CONNECTION_KEYS` (`kit/seal`), bound to the connection id and the field; every write seals with the newest key and `Rekey` reseals the rest.
- Lifecycle (`status` `active`, `needs_reauth`, `disconnecting`; `version`, `refresh_owner`, `refreshing_until`): a token within a minute of expiry is refreshed once per process (singleflight), detached from the caller's context. A short transaction locks the row and, if the token is still stale and no lease is live, takes a lease (the provider timeout plus 15 s) and commits. The provider call runs outside any transaction; the new tokens are written conditioned on the lease owner and version, retrying only the write on deadlocks and uncertain commits. Callers that find a live lease wait with backoff holding no connection (`ErrBusy` after the lease length). `invalid_grant` marks the connection `needs_reauth` (`ErrReauthRequired`). A refresh whose write finds the row changed revokes the tokens it got. 429 and 5xx are retried up to three times with backoff (or `Retry-After` in seconds or as a date, capped at 30 s) when the request can be replayed.
- Disconnect and reconnect wait while a refresh holds the lease. Disconnect marks the row `disconnecting` (version bumped), revokes at the provider outside any transaction, then deletes the row at that version (`ErrChanged` if a reconnect replaced it meanwhile); a failed revocation restores the status so the caller can retry.
<!-- /part:connections -->

### seal (core helper)
`seal.NewKeyring(secrets, purpose)`, `k.Seal(plain, aad)`, `k.Open(sealed, aad) (plain, stale, err)`: AES-256-GCM with HKDF-SHA256 keys per purpose, newest key first; `stale` means an older key opened it, and callers reseal such values on their next write. Rotation procedure: [security.md](security.md#9-secrets).

### cli (core)
`cli.App{Name, Summary, Commands}.Main()`, `cli.Command{Name: "queue:retry", Summary, Flags func(*flag.FlagSet), Run func(ctx, fs, args) error}` (output to `fs.Output()`); `list` and `--help` built in; `cli.JSONFlag`, `cli.WantsJSON` and `cli.Print(w, asJSON, cli.Table{...})` for tabular output; `cli.Usagef` for a usage error. Commands stop on SIGINT and SIGTERM through `ctx`.

### webhook (core)
`v, err := webhook.NewVerifier(webhook.Options{Source, Secrets, Tolerance, Production})` (one verifier per sender; `Source` names it; secrets `whsec_...`, newest first, at least 24 decoded bytes in production), `v.Verify(ctx, webhook.Headers{ID, Timestamp, Signature}, body)` (embed `Headers` in a Huma input; `webhook.HeadersOf(h)` for plain handlers): rejects missing headers, an id that is not 1 to 255 printable ASCII characters, a timestamp outside the tolerance (default 5 min) and any body without a matching `v1,` signature, in constant time; it computes each secret's MAC once and compares at most five signatures. `webhook.Mapper` answers every failure with the same 401. `webhook.Sign(secret, id, ts, body)`. `v.Seen(ctx, tx, id)` records `(source, id)` in the caller's transaction and reports a replay, since ids are unique only per sender; `webhook.Prune(ctx, tx, before)`.

A sender that signs with the timestamped hex scheme (`t=<unix>,v1=<hex HMAC-SHA256 of "{t}.{raw body}">`, as Stripe does) gets `v, err := webhook.NewTimestampedVerifier(webhook.TimestampedOptions{Source, Secrets, Tolerance, Production, Header, IDHeader, IDField})`: `Header` names the signature header, and the delivery id comes from the `IDHeader` header or the `IDField` top-level string field of the signed JSON body (set one; the body field is signed, a header is not). Secrets are used as they are, newest first, at least 24 bytes in production. `id, err := v.Verify(ctx, r.Header, body)` refuses a missing or malformed header (no `t`, two `t`, an entry that is not `key=value`), a time outside the tolerance and a body without a matching `v1=` signature (other schemes skipped, at most five compared, constant time), then a missing or invalid delivery id (`ErrDeliveryID`); `v.Seen(ctx, tx, id)` records it as above. `webhook.SignTimestamped(secret, ts, body)`; `webhook.Mapper` answers these failures with the same 401.

## Async and IO

### jobs (core)
```go
q, err := jobs.New(jobs.Options{Config: cfg.Jobs, Tx: jobs.PlainTx(d), Metrics: jobs.Metrics{Claimed, Finished}, Trace: trace, Build: buildTime}) // jobs.OperatorTx(access) under tenancy; Trace wraps each run (otelx.Jobs)
q.Handle("notes.digest", jobs.Typed(fn), jobs.Lane("slow"), jobs.Timeout(5*time.Minute), jobs.MaxAttempts(5), jobs.Backoff(f), jobs.RetainPayload(72*time.Hour))
id, err := q.Enqueue(ctx, tx, "notes.digest", payload, jobs.At(t), jobs.Unique(key), jobs.Priority(10), jobs.Lane("fast"), jobs.MaxAttempts(3))
q.Schedule("notes.digest", "notes.digest", "0 7 * * 1-5", loc) // name, kind, cron spec, location
err = q.Run(ctx, lanes...)                                     // workers, scheduler, lease reaper; a server background func
jobs.Permanent(err), jobs.RetryAfter(d, err), jobs.ClearPayload(ctx, tx, id), jobs.Redact(s)
n, err := q.Overdue(ctx)                                       // running jobs past their lease and unreaped (doctor)
jobs.Commands(open)                                            // queue:*, schedule:*, worker
```
- Enqueue joins the caller's transaction (`db.Transaction`, so a tenant transaction too); the kind must be registered. `Unique` dedupes while a job with the key is queued or running (a partial unique index on Postgres, a functional unique index on MySQL) and returns that job's id; on MySQL the twin is found with a locking read, so it is seen even when it committed after the transaction's snapshot. A MySQL enqueue that finds a twin holds a lock on it until the caller commits, which delays that job's renewal and outcome; keep enqueueing transactions short. Payloads are JSON, at most 256 KiB. `PlainTx` runs the queue's bookkeeping read committed, so a MySQL claim locks only the row it takes.
- Workers claim with `FOR UPDATE SKIP LOCKED`, highest priority then earliest `run_at`, in the lane's partial index (open jobs only on Postgres). Each claim gets its own token in `locked_by`, and every outcome is written fenced by it, so a worker that lost the job changes nothing.
- Leases and `run_at` use `clock.Wall`, never the business clock. The lease is renewed every third of `APP_JOBS_LEASE`; when a renewal cannot be confirmed the handler's context is cancelled at the moment the last confirmed lease runs out, and the reaper (also every third of the lease) returns expired jobs to the queue, so two workers never run one job past that point. A renewal that finds the job gone (cancelled, reaped) cancels at once.
- Outcomes: the cancellation cause decides first. A shutdown releases the job without spending the attempt even if the handler returned nil; a lost lease records nothing, and the reaper requeues the job after the kind's backoff or fails it when its attempts are spent. Otherwise nil is `done`; `Permanent` or spent attempts is `failed`; other errors retry after exponential backoff with full jitter (5 s base, 1 h cap) or the handler's `Backoff`, or `RetryAfter`'s delay. A panic is a permanent failure with code `panic`. On shutdown, handlers get `APP_JOBS_SHUTDOWN_GRACE`; then their context is cancelled and the job is requeued without spending the attempt. `queue:retry` gives up the job's unique key, which an open twin may hold by now. A kind this process does not know is released for 30 s, also without spending one (a newer release running beside it may know it); an hour after the job was enqueued it fails with `unknown_kind` instead. `last_error` is redacted (emails, query values, long tokens) and capped at 1000 characters; `last_error_code` comes from `jobs.Coded` errors.
- Schedules: rows in `job_schedules` synced from code at `Run`; each tick locks due rows with `SKIP LOCKED`, enqueues the slot with a unique key, and moves `next_run_at` to the next slot after now (missed slots run once). Specs are gronx cron expressions, read in the schedule's location. A row records the `Options.Build` stamp that wrote it: the build time in RFC 3339 UTC (`2026-10-23T12:00:00Z`, at most 64 characters; `New` refuses any other form, which would not sort as time). A process changes a stored schedule only when its stamp sorts at or after that one, an unstamped build never changes a stamped row, and every process computes the next slot from the stored spec, so two releases side by side during a deploy do not rewrite each other. A rollback keeps the newer build's specs until a build newer still changes them.
- Tenancy: `Enqueue` writes the context's tenant; a claim reads it and the handler's context carries it (`Job.Tenant`, `db.TenantOf`), so its transactions are that tenant's. A job without a tenant runs only when its kind is registered `jobs.Global()` (maintenance, schedules, `mail.send`); any other fails with `no_tenant`.
- Retention: `New` registers `jobs.prune` hourly: done and cancelled jobs after `APP_JOBS_RETAIN_DONE`, failed after `APP_JOBS_RETAIN_FAILED`, and payloads of kinds with `RetainPayload` cleared; in batches of 1000.

<!-- part:mail -->
### mail (optional)
```go
r, err := mail.NewRenderer(appTemplates)                  // fs.FS or nil; <name>.txt (subject, content), <name>.html, layout.txt, layout.html
smtp, err := mail.NewSMTP(cfg.Mail.SMTP)                    // or mail.Log{}, &mail.Recorder{} in tests
err = smtp.Probe(ctx)                                        // connect, TLS, AUTH, QUIT before MAIL FROM (doctor)
svc, err := mail.New(mail.Options{Queue: q, Tx: jobs.PlainTx(d), Mailer: smtp, Renderer: r, Config: cfg.Mail})
id, err := svc.Enqueue(ctx, tx, mail.Email{To, Template, Data, Sensitive})
n := svc.Notifier(mail.DefaultLinks(cfg.App.PublicURL))   // reset, verify and invite links; enqueues in the caller's tx
```
- `Enqueue` renders in the caller's transaction (template errors surface there), fixes a Message-ID (`<uuidv7@from-domain>`) for every attempt, and writes the outbox's `queued` row.
- The `mail.send` job writes `sending` in its own transaction before talking to the server. A run that finds `sending` (a crash or a lost outcome after it) writes `uncertain` and stops without sending; so does a send error that is not a certain refusal. Only errors wrapped with `mail.NotSent` (connection, STARTTLS, auth, MAIL FROM, RCPT TO, DATA refused, or a reply code to the final dot) become `failed` and are retried when temporary. The outbox is append-only: each transition takes the next `seq` of its message (`unique (message_id, seq)`), the current state is the highest `seq`, and a run whose insert conflicts (another run moved the message) records nothing and stops as uncertain, so two runs at once send once. Host clocks never order it. A retried job whose body was cleared fails with a permanent error instead of reporting success.
- SMTP through go-mail: STARTTLS required of the server by default (TLS 1.2+), implicit TLS with `tls`, `none` only to loopback; timeouts. The kit's default templates (`reset`, `verify`, `invite`) and layouts are used unless the app's file system has its own with the same name. Links carry the token in the URL fragment, which browsers never send to a server.
- Bodies are cleared from finished jobs after `APP_MAIL_RETAIN_BODY`; `Sensitive` bodies (the notifier's links) in the same transaction that records `sent` or a final `uncertain`, including the crash-recovery path. `mail.prune` removes outbox rows after `APP_MAIL_RETAIN_LOG`.
<!-- /part:mail -->

<!-- part:files -->
### files (optional)
`files.Config` with an empty `Driver` (`files.DriverNone`, the default) leaves files off: `cfg.Enabled()` is false and `files.Open` refuses. `files.Storage` (`Put`, `Get`, `Stat`, `Delete`, `List`); `files.NewLocal(root)` (through `os.Root`; temporary file, size and checksum check, fsync, rename, fsync of both directories; `List` reads directories in batches), `files.NewS3(ctx, opts)` (AWS SDK v2, any S3-compatible endpoint, SSE AES256 unless `DisableSSE`, SHA-256 checksum sent, presigned links); `files.Open(ctx, cfg)` picks one and `cfg.Inspector()` builds the inspector. `files.NewService(files.Options{Storage, Inspector, Scanner, Policies, TempDir, KeyPrefix, Signer, Tx})` with a `files.Policy{MaxBytes, Types, Inspect, Visibility, Presign}` per kind and `files.PlainTx(d)` (or a tenant runner) as `Tx`:
```go
by := files.Uploader{Kind: string(p.Kind()), ID: p.Subject()}                 // the principal; files.SystemUploader for jobs
r, err := svc.Put(ctx, files.Upload{Kind: "avatar", Name: name, Body: body, By: by}) // outside any transaction: spool, hash, detect, inspect, pending row, object
f, err := svc.Stage(ctx, tx, r.ID, by)                                          // in the caller's transaction; only the uploader
err = svc.Attach(ctx, tx, f.ID, "avatar", files.Owner{Type: "users", ID: userID}, by)
err = svc.Remove(ctx, tx, f.ID)                                                 // row now, object after commit
res, err := svc.Sweep(ctx, files.SweepOptions{MinAge, TTL, Batch})              // unclaimed files and orphan objects
url, err := svc.PublicURL(ctx, f, ttl)                                          // signed for fileshttp.Public; presigned only with Policy.Presign
```
Keys are `<KeyPrefix>f/<ab>/<cd>/<32 hex>`, with the tenant after `f/` under tenancy (`f/<tenant>/<ab>/...`); `Open` refuses a key of another tenant than the context's, and signed links carry and sign the tenant, which `fileshttp.Public` reads the file in. `files/inspect`: `inspect.New(limits, concurrency)` with `Detect` (type from content) and `Inspect` (PNG and JPEG re-encoded; GIF and WebP size-checked and kept with their metadata); `inspect.Scanner` is the antivirus hook. `fileshttp.Options{Files, Authorize, Load, Signer, Admit, Uploader, WriteTimeout, UploadTimeout}`: `Authorize` loads a file for `Private`; `Load`, `Signer` and `Admit` serve `Public`, where `Admit(ctx, tenant)` runs once a link verifies and before its tenant becomes the context's (under tenancy it refuses another tenant than the host's, or a suspended or gone one, as not found; nil panics). `fileshttp.Private(opts)` and `fileshttp.Public(opts)` serve downloads named by the `{fileId}` path parameter (`fileshttp.IDParam`); `fileshttp.Upload(opts, kind)` is a plain handler that streams a raw body (name from `Content-Disposition`) or one multipart file part to `Put` and answers 201 with the `files.Receipt` in the data envelope (mount it outside any global body cap; `Options.UploadTimeout` extends the read and write deadlines for it, as `WriteTimeout` does for downloads); `files.Mapper` maps the errors.
<!-- /part:files -->

<!-- part:xlsx -->
### xlsx (optional)
`xlsx.NewReader(r, xlsx.Limits{MaxBytes, MaxSheets, MaxRows, MaxCells, MaxUnzippedBytes})` then `Rows(sheet)` streams rows with typed accessors (`String`, `Int`, `Decimal`, `Bool`, `Date`); rows and cells count across the workbook. `xlsx.NewWriter(w)`, `Sheet(name)`, `Row(cells...)`, `Close()` streams sheets, neutralises formula-like strings with `csvx.Neutralise`, writes numbers and dates as typed cells (a decimal becomes a float cell, so write money as integer minor units or as text). Wraps excelize.
<!-- /part:xlsx -->

<!-- part:barcode -->
### barcode (optional)
`barcode.QR(content, size, level) ([]byte, error)` (PNG), `barcode.QRSVG`, `barcode.Code128`, `barcode.EAN13` (validates the check digit). Wraps boombuler/barcode.
<!-- /part:barcode -->

<!-- part:pdf -->
### pdf (optional)
`pdf.Gotenberg(cfg, httpClient).HTMLToPDF(ctx, html, assets...) ([]byte, error)`: basic auth, timeout, size cap, `%PDF-` check; `pdf.ErrUnavailable` when the renderer is down (retry later).
<!-- /part:pdf -->

### csvx (core)
`csvx.NewWriter(w, header...)` (BOM, CRLF, every cell quoted, formula neutralised including full-width forms; `csvx.Number` cells that are numbers skip neutralising; `Flush` when done), `csvx.NewReader(r, csvx.Limits{MaxRowBytes, MaxFieldBytes, MaxFields, MaxRows})` (strips BOM, stops reading once a row passes its limit).

<!-- part:otel -->
### otelx (optional)
```go
shutdown, err := otelx.Start(ctx, cfg.Otel, otelx.Resource{Service, Version, Environment}) // nothing without cfg.Endpoint
router.Use(otelx.Middleware(service))                // server span and request metrics per route pattern; service is the fixed server.address
db.Open(ctx, cfg.Database, db.Connector(otelx.OpenDB)) // a span per query (otelsql), both engines
trace, metrics := otelx.Jobs()                       // jobs.Options{Trace, Metrics}: a span per run named after the kind; wait and run times
logx.New(cfg.Log, w, logx.ContextAttrs(otelx.LogAttrs)) // trace_id and span_id on records logged inside a span
```
OTLP over HTTP to `Endpoint` (no credentials in it; they go in `Headers`), parent-based sampling at `Sample`, TraceContext propagation. Inbound requests are a public endpoint: a caller's `traceparent` becomes a link on a new root span, so clients cannot force sampling or plant trace ids. `/livez` and `/readyz` are not traced. No span carries a client address (`client.*` and `network.peer.*` are dropped at export, whichever instrumentation set them); query strings and bodies are not recorded; failed jobs and queries record `error.type`, never the error's text. `LogAttrs` gives ids only for sampled spans. `Install` takes the exporter and reader directly (tests use the SDK's in-memory ones).
<!-- /part:otel -->

<!-- part:docx -->
### docx (optional)
Small OOXML writer: `docx.New(docx.Styles{...})` with `Heading`, `Paragraph`, `Text`, `List`, `Table`, `PageBreak`, `TableOfContents`, then `Write(w)`; `docx.Validate(r, size)` checks the structure.
<!-- /part:docx -->

### money (core)
`money.Amount{Minor int64, Currency string}`; `money.New(minor, code)`, `Add`, `Sub` (error on currency mismatch or overflow), `Allocate(weights...)` (splits without losing a minor unit), `FromDecimal(d, code, money.HalfEven)`, `Format(locale)`. The zero `Amount` refuses to marshal; `amount` is documented as within plus or minus 2^53-1. Exponents from `bojanz/currency`. Rates and percentages use `shopspring/decimal`, converted to money once with a named rounding mode.

### dates (core)
`dates.Date{Year, Month, Day}` with `Parse`, `String`, `In(loc)`, `AddDays`, `Compare`, JSON and SQL scanning. Documented as `format: date`; years 0001 to 9999 and real calendar dates only, enforced on every way in and out. Parse errors never echo the input.
