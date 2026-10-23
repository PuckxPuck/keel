# PlatformKit compared with keel (2026-10-22)

Source read: `github.com/septagon-oss/platformkit` v1.1.1 (Apache-2.0, by Septagon), its README, ARCHITECTURE.md, 13 ADRs and selected packages. Read as data; nothing was run.

## What it is

A Go foundation for multi-tenant SaaS, consumed as a versioned library. Kernel (`kit/`: db, tenancy, httpx, crud, entity, events, jobs, limit, flags, locale, problem) plus reference modules (auth, user, tenant, audit, billing, content, file, notification, site, task, admin, web) and a server-rendered UI layer (gomponents, HTMX, generated admin screens, a component gallery). About 82,000 lines of Go, 177 test files, browser and end-to-end suites.

Facts that matter for judging it:
- v1.0.0 on 2026-09-03; v1.1.0 on 2026-09-18 broke source compatibility (71 exported changes). Its changelog says no consumer was on the stable line: the company's own products pin `main`.
- Hundreds of automated "proof" pre-release versions, several a day through October 2026: heavy automation, likely agent-driven development.
- In practice it is one company's internal foundation, published. Adoption by others is not visible.

## Where it is stronger than keel's design

| Area | PlatformKit | keel before this review |
| --- | --- | --- |
| Exists and runs | Working code, tests, a local start command with embedded Postgres | Design only |
| Tenant transactions as types | `Tx[Tenant]` and `Tx[System]` are distinct types; repositories accept only `Tx[Tenant]`; the system handle can only be minted inside the kernel. Cross-tenant code is a compile-time choice and one grep | Separate pools and roles, but stores took any transaction |
| Setting rewrite | Documents that the tenant setting is a placeholder any role can rewrite with `set_config`, guards it with a build script that bans writing it outside `kit/db` (in Go and SQL), and re-reads the setting before commit | Not addressed |
| Security counters across replicas | Login lockout and code redemption limits are rows in Postgres, so every replica sees one count and a deploy does not reset it | In-memory buckets only |
| Operator permissions | Learned the hard way that a control-plane route on tenant hosts was reachable by any tenant admin holding a wildcard; operator permissions now never match a wildcard and are refused on non-operator tenants | Separate operator realm and host already avoid this; no wildcards |
| Breadth of product modules | Billing (provider-agnostic), content, notifications, files, sites, admin screens, i18n, feature flags (OpenFeature) | Not in scope (no UI); billing and content left to apps |
| Scale-out events | Outbox relayed to NATS JetStream when several workers run | Jobs table polled by workers |

## Where keel's design is stronger (for API-first products)

| Area | keel | PlatformKit v1.1.1 |
| --- | --- | --- |
| UI-agnostic | No UI; any client generates from OpenAPI | Ships a server-rendered UI layer and admin generator; bloat for a Vue or mobile front end |
| Query layer | Jet: typed SQL builder, no reflection on the request path | GORM in the kernel transaction type, plus lib/pq and pgx |
| Machine access | Tenant API keys with scopes, a public `api` realm with its own spec and breaking-change gate | No API keys |
| MFA | TOTP with recovery codes, passkeys, step-up, device tokens | None found |
| Webhooks | Inbound verification and outbound tenant endpoints with SSRF-safe delivery | None found |
| Calling other services as a tenant | `connections` with encrypted tokens and locked refresh | None found |
| Pagination and sync | Signed keyset cursors, capped totals, commit-safe change feeds with tombstones for offline clients | Offset paging (max 200) |
| Database choice | Postgres, or MySQL without tenancy | Postgres only |
| Observability | OpenTelemetry when configured | No OpenTelemetry found |
| Money | Integer minor units type | Left to products |
| Least privilege for migrations | Only the release step holds owner credentials | Every process migrates at boot, so every process holds owner credentials |
| Ownership model | Template: the app owns its code, no forced upgrades | Library: apps track breaking releases (one already, two weeks after 1.0) |
| Dependencies | Small, listed with reasons | GORM, NATS, gRPC, OpenFeature, an authorizer SDK, embedded Postgres, goldmark, bluemonday, gomponents |

## Verdict

- **For API-first apps, keel fits better.** PlatformKit lacks API keys, MFA, webhooks, keyset paging and offline change feeds, and brings GORM and a server UI an API-first app does not want.
- **As an open-source project, they occupy different lanes.** PlatformKit is a full-stack SaaS foundation with its own UI. keel would be an API-first, UI-agnostic template with integrations and offline sync built in. The overlap is the tenancy kernel, where PlatformKit's thinking is excellent.
- **What keel took from it** (decisions D29 to D31):
  1. Typed tenant and operator transactions, so stores cannot be handed the wrong kind.
  2. A guard against rewriting the tenant setting: a lint banning it outside `kit/db` in Go and SQL, plus a re-read before commit.
  3. Security counters (sign-in failures, MFA attempts, code redemption, reset requests) stored in the database so they hold across replicas and deploys; general traffic limits stay in memory.
