# Testing

`make test` runs the Go tests with `-race` against a real database. `make check` adds lint, govulncheck and the generated-code drift check. Both pass before a PR.

## Budget
- `make test` stays under 3 minutes on a laptop; `keel check` under 5. A PR's CI finishes in under 10 minutes wall time. These are limits, not targets: a phase that pushes past them cuts or merges tests before it adds more.
- A test earns its place by guarding behaviour a user, an operator or a security property depends on, or a bug that already happened. Coverage is not a goal. Do not test getters, constructors, framework behaviour, or the same rule once per layer.
- One table test per rule; one integration test per behaviour that matters; walk tests instead of one test per operation.
- Each phase report states the added test time; more than 20 seconds added needs a reason.

## Layers
- **Pure rules** (state machines, guards, calculations, parsers): table tests, milliseconds, one table per rule.
- **Services and handlers**: integration tests against the real database through the API (`httptest` plus the Huma API). One test per behaviour that matters: happy path, each refusal (403, 409, 422), and each rule.
- **Kit packages**: unit tests for pure parts; contract tests run on both engines (`make test-pg`, `make test-mysql`) for anything with SQL.

## Database in tests
- `testdb.Main(m, opts)` in each package's `TestMain` gives the package one database cloned from a template migrated once per run; tests isolate by unique data and run with `t.Parallel()` where they share no rows.
- `testdb.Isolated(t)` when a test needs its own database (migrations, destructive tests).
- Tests connect as the app role, never the owner, so row-level security applies in tests exactly as in production; on MySQL as a run's user with the app user's production grants. A test that must act beyond them (tampering with the audit log, watching lock waits) takes `e.Owner(t, d)`.
- No mocks for the database. Fakes are fine for mail (`mail.Recorder`), storage (a temp dir), PDF, and other modules' interfaces.

## Walk tests (one each, picked up automatically)
- **Operation walk**: every registered operation has a `Need`, a rate-limit class, an `OperationID`, tags and documented errors, and its output schema is one of the envelopes.
- **Error walk**: unknown route, wrong method, oversized body, malformed JSON and a forced panic all answer problem+json.
- **Public API walk** (with `apikeys`): only operations marked `httpx.Public` answer on the api host; a key without the scope gets 403.
- **Permission walk**: every write operation called as a principal without the needed permission returns 403; with it, it does not.
- **Audit walk**: every write operation that succeeds leaves at least one `audit_log` row in its transaction.
- **Tenant walk** (with tenancy): every operation called in tenant A with tenant B's ids returns 404 and changes nothing; the RLS catalogue test passes.
- **Realm walk**: every operation answers only on its realm's hosts.
- **List walk**: every list operation has a `limit` maximum and rejects an unknown sort; its keyset walk returns every matching row exactly once while rows are inserted and deleted between pages; a cursor reused with other filters is refused.
- **Feed test** (where feeds exist): a transaction that starts before a read and commits after it still appears in the next page; deletes arrive as tombstones.

## Fuzz and benchmarks
- Every parser of outside input has a fuzz target. On PRs only its seed corpus runs, as an ordinary fast test; actual fuzzing (minutes per target) runs nightly.
- Hot paths have benchmarks. They run on demand (`keel bench`) and nightly, never on every PR.

## What CI runs
- Pull requests: lint, govulncheck, and tests on the app's primary engine and current version only, in parallel jobs.
- Main and nightly: the full database matrix (Postgres 17 and 18, MySQL 8.4 and 9.7 while keel supports both), fuzzing, benchmarks.
- A PR that changes `internal/kit/db` or migrations also runs the full matrix.

## Time and randomness
- Pin time with `clock.WithFixed`. Never depend on the real date or sleep. Use `testing/synctest` for code with timers.
- Deterministic ids in fixtures via `ids.Stable`.

## Style
- `require` for preconditions, `assert` for the checks; no other assertion libraries.
- Test names describe behaviour: `TestApprove_RefusesWhenLocked`.
- Fixtures built once per package (`sync.Once` or `TestMain`), not per test.
- No snapshot tests of JSON; assert the fields that matter.
