# AGENTS.md

Read this first. It is the entry point for every agent (Claude, Codex) and every person working in this repo.

<!-- part:keel -->
keel is a Go backend template: make an app from it with `keel init` to start or port a service.
<!-- /part:keel -->
No UI. Kit code under `internal/kit/` is app-agnostic, so improvements travel between keel and the apps made from it as diffs (`keel upgrade:diff`).

## Read before you work

| You are touching | Read |
| --- | --- |
| Anything | [docs/README.md](docs/README.md) |
| Shape of the system | [docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md) |
| Security-relevant code (auth, rbac, httpx, files, webhook, config) | [docs/security.md](docs/security.md) |
| Go code | [docs/conventions/go.md](docs/conventions/go.md) |
| Endpoints | [docs/conventions/api.md](docs/conventions/api.md) |
| Schema and queries | [docs/conventions/database.md](docs/conventions/database.md) |
| Tests | [docs/conventions/testing.md](docs/conventions/testing.md) |
| A new module | [docs/conventions/modules.md](docs/conventions/modules.md) |
| A kit package | [docs/packages.md](docs/packages.md) |
| A dependency | [docs/stack.md](docs/stack.md) |
| Commands | [docs/cli.md](docs/cli.md) |

<!-- part:keel -->
In keel itself, read the current plan in [docs/plans/](docs/plans/) before anything else.
<!-- /part:keel -->
<!-- part:tenancy -->
- Anything tenant-scoped: [docs/tenancy.md](docs/tenancy.md).
<!-- /part:tenancy -->
<!-- part:apikeys -->
- API keys and the public API: [docs/integrations.md](docs/integrations.md).
<!-- /part:apikeys -->
<!-- part:webhooks -->
- Outbound webhooks: [docs/integrations.md](docs/integrations.md).
<!-- /part:webhooks -->
<!-- part:connections -->
- Connections to other services: [docs/integrations.md](docs/integrations.md).
<!-- /part:connections -->

## Commands

| Command | Does |
| --- | --- |
| `make up` | Start the local database and services (127.0.0.1 only) |
| `make seed` | Local only, with `.env` loaded: migrate, then setup and seed |
| `make dev` | Run the API |
| `make gen` | Jet schema types and OpenAPI; run after any migration or operation change |
| `make test` | Go tests with `-race` on a real database |
| `make check` | Lint, govulncheck, tests, generated-code drift. Must pass before a PR |
| `go run ./cmd/app doctor` | Checks configuration, database, roles, RLS, queues, mail, files, keys |
| `go run ./cmd/keel make:module <name>` | Scaffold a module that already passes `check` |

Dev servers and long builds are run by the human; agents say the command.

## Hard rules

1. **Kit stays generic.** Nothing in `internal/kit/` names a product concept, imports a module or `internal/app`, or reads env directly.
2. **Modules talk through interfaces** declared by the consumer and wired in `internal/app`. Queries live only in a module's `store.go`; never query another module's tables.
3. **Contract from code.** Operations are declared with Huma; `make gen` writes `spec/<realm>.openapi.yaml`. Never hand-edit generated files.
   Every response is the `data` envelope or problem+json; nothing else compiles as an operation output.
4. **The server enforces every rule.** Every operation declares a `Need` and a rate-limit class; services check contextual rules again. Code checks permissions, never role names.
5. **One transaction per change.** Rows, `audit.Record`, and enqueued jobs commit together. Side effects outside the database go in `db.AfterCommit` or a job.
6. **No silent overwrites.** Editable rows carry `version`; stale writes are 409.
7. **Client IP only through `httpx.ClientIP(ctx)`.** Never read forwarding headers or `RemoteAddr` yourself; never grant access by IP.
8. **Time through the clock.** `clock.Business` for domain dates, `clock.Wall` for expiry and leases. No `time.Now()` in domain code.
9. **Migrations are append-only** and safe for the running release. One statement per file on MySQL. Never wipe or reset a shared database.
10. **Money is integer minor units** with a currency code. No floats anywhere near money.
   Typed ids and typed enums in domain code; no `any`, no `unsafe`, no cgo.
11. **No secrets or personal data** in git, logs, errors, or test fixtures.
12. **No new dependency** without a line in `docs/stack.md` saying why.
13. **Tests ship with the code.** A task is done when `make check` passes and the docs that describe the behaviour are updated. Only meaningful tests: rules, refusals, security properties and past bugs. `make test` under 3 minutes, PR CI under 10.
14. **Few comments.** Only a non-obvious why, in a line or two; never a story. Applies to config files too.
15. **No emoji** anywhere. No AI attribution in commits or PRs.

<!-- part:tenancy -->
Under tenancy, also:
- **Never write the tenant into a query.** Row-level security and the column default do it.
- **Tenants are separated by the database.** Every tenant table has `tenant_id`, row-level security enabled and forced, and tenant-scoped keys. Cross-tenant work uses the operator pool, never a loosened policy. Tests run as the app role.
<!-- /part:tenancy -->

## Definition of done
- Acceptance criteria in the plan met.
- `make check` green on both databases while keel itself is the repo (apps test their one engine).
- Reviewed against [docs/security.md](docs/security.md#11-checklist-for-a-new-endpoint) for any new operation.
