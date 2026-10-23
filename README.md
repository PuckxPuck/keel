# keel

<!-- part:keel -->
A Go backend template: the Laravel experience for Go, without the runtime magic. Copy it to start a new service or to port an existing one, and get on day one: configuration, a code-first OpenAPI API with consistent errors, sessions and sign-in with MFA, roles and permissions, optional multi-tenancy with an operator realm, audit, rate limits, Postgres or MySQL with migrations, background jobs, mail, file storage, tests, CI and deploy files. No UI; bring your own client.

Status: v1 built. Plan and reviews: [docs/plans/2026-10-22-keel-v1.md](docs/plans/2026-10-22-keel-v1.md).

## Start an app

```
git clone <keel> shop && cd shop
go run ./cmd/keel init --module example.com/me/shop --name shop --db postgres --without pdf,docx
cp .env.example .env && make up
make seed
make dev
```

`keel init` keeps one database, removes the parts you name, rewrites the module path, name and settings prefix, then builds the app and runs `keel gen` and `keel check`; a failure resets the checkout. Commit the result. Flags and parts: [docs/cli.md](docs/cli.md#init).
<!-- /part:keel -->

## Docs

- [AGENTS.md](AGENTS.md): rules and commands, start here
- [docs/architecture.md](docs/architecture.md): system, layers, request lifecycle
- [docs/security.md](docs/security.md): controls, production profile, threat model
<!-- part:tenancy -->
- [docs/tenancy.md](docs/tenancy.md): optional multi-tenancy on Postgres row-level security
<!-- /part:tenancy -->
- [docs/integrations.md](docs/integrations.md): API keys, public API, outbound webhooks, connections
- [docs/cli.md](docs/cli.md): artisan-style commands
- [docs/packages.md](docs/packages.md): kit package catalogue
- [docs/configuration.md](docs/configuration.md): every setting
- [docs/operations.md](docs/operations.md): build, deploy, migrate, observe, back up, upgrade
- [docs/porting.md](docs/porting.md): moving an existing app onto keel
- [docs/conventions/](docs/conventions/): Go, API, database, testing, modules
- [docs/decisions.md](docs/decisions.md), [docs/stack.md](docs/stack.md)
