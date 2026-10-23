# docs

| Doc | Answers |
| --- | --- |
| [architecture.md](architecture.md) | How the system fits together and why the layers are shaped this way |
| [security.md](security.md) | What is protected, how, and the checklist for new endpoints |
| [integrations.md](integrations.md) | API keys and the public API, outbound webhooks, connections to other services |
| [cli.md](cli.md) | Every `app` and `keel` command, including `doctor` |
| [packages.md](packages.md) | What each kit package offers |
| [configuration.md](configuration.md) | Every environment variable and its default |
| [operations.md](operations.md) | Build, deploy, migrations in deploys, observability, backups, incidents, upgrades |
| [porting.md](porting.md) | Moving an existing app (Laravel or Go) onto keel |
| [conventions/go.md](conventions/go.md) | How Go code is written |
| [conventions/api.md](conventions/api.md) | How endpoints look |
| [conventions/database.md](conventions/database.md) | Schema, types per engine, queries, migrations |
| [conventions/testing.md](conventions/testing.md) | What to test and how |
| [conventions/modules.md](conventions/modules.md) | Steps to add a module |
| [decisions.md](decisions.md) | Why things are the way they are |
| [stack.md](stack.md) | Every dependency with its reason and version |

<!-- part:tenancy -->
- [tenancy.md](tenancy.md): multi-tenancy: model, row-level security, database roles, operator realm.
<!-- /part:tenancy -->
<!-- part:keel -->
- [plans/2026-10-22-keel-v1.md](plans/2026-10-22-keel-v1.md): what was built, in what order, how each phase was accepted, and its reviews.
- [research/](research/): comparisons with other projects (PlatformKit).
<!-- /part:keel -->

Docs describe behaviour the code has. When code changes behaviour, the doc changes in the same commit.
