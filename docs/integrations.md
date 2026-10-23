# Integrations

How other software talks to an app built on keel, and how the app talks to other software. Three parts, each optional at `keel init`:
<!-- part:apikeys -->
- `apikeys` and the `api` realm. Others call us: a storefront plugin reads products and pushes orders.
<!-- /part:apikeys -->
<!-- part:webhooks -->
- `webhooks` (outbound). We notify others: stock changed, order paid, so a plugin updates its store.
<!-- /part:webhooks -->
<!-- part:connections -->
- `connections`. We call others with the tenant's account: post invoices to an accounting service under the tenant's own login.
<!-- /part:connections -->

All three are tenant-scoped when `tenancy` is kept.

Inbound webhooks (others notify us) are core: `kit/webhook` verifies a sender's deliveries with Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`) or with the timestamped hex scheme many providers use (`t=<unix>,v1=<hex>` in a header the app names, the delivery id from a header or the signed body), with several secrets for rotation, a five-minute tolerance and the delivery id recorded per sender in the transaction that applies it ([packages.md](packages.md#webhook-core)).

<!-- part:apikeys -->
## 1. API keys

### What a key is
A key belongs to a tenant, not to a person. It acts as a service principal inside that tenant with a fixed set of scopes. It keeps working when the person who made it leaves.

### Format
```
<prefix>_<env>_<id>_<secret><checksum>
myapp_live_01JB8Q3Z6T4M9X2K5W7R1N0P3S_5fKc...Xq9 (secret 32 random bytes, base62; checksum CRC32 base62)
```
- `prefix` is the app's short name (`APP_APIKEY_PREFIX`, else the app name when it is 2 to 16 lower case letters and digits); `env` is `live` in production and staging, `test` elsewhere, and a server accepts only its own. The shape is recognisable by secret scanners (GitHub secret scanning, gitleaks), so a key pushed to a public repo can be reported and revoked automatically. The pattern for a scanner: `<prefix>_(live|test)_[0-7][0-9A-HJKMNP-TV-Z]{25}_[0-9A-Za-z]{49}`.
- `id` is the key's public UUIDv7 in Crockford base32 (26 characters, upper case), used to find the row; the secret (32 random bytes, 43 base62 characters) is compared in constant time against its SHA-256. The secret has 256 bits of entropy, so a fast hash is correct here (argon2id is for low-entropy passwords).
- The checksum (CRC32 of everything before it, 6 base62 characters) lets the server reject typos and random strings before touching the database.
- The full key is shown once at creation. Only the prefix and the last four characters (`hint`) are shown afterwards.

### Table
`api_keys`: `tenant_id` (added by the tenancy migration), `id`, `name`, `hint`, `secret_hash`, `scopes` (permission codes, space separated), `created_by`, `created_at`, `expires_at` (optional), `expiry_reminded_at`, `last_used_at` and `last_used_ip` (updated at most once a minute, and skipped rather than waited for when another transaction holds the row), `allowed_cidrs` (optional, space separated), `revoked_at`, `revoked_by`, `rate_class` (optional: a rate-limit class that replaces `api-key` for this key, set with `apikey:create --rate-class`).

### Scopes
- The permission catalogue marks which permissions may be given to a key (`APIGrantable: true`). Account and access management are never grantable.
- Creating a key needs `api_keys.manage`, and a person can only grant scopes they hold themselves (the same guardrail as roles). The checks live in the apikeys service's `Create`, which refuses with 422 `checks_failed` and the rules `unknown_permission`, `not_api_grantable` and `grant_exceeds_actor`; `apikey:create` acts as the system, which skips only the last.
- A request with a key passes `Need` only for its scopes. Contextual service checks see an `apikey` actor and decide what that means (for example, a key cannot approve its own submissions).

### Using a key
- `Authorization: Bearer <key>` on the `api` realm's host (for example `api.example.app`). Never in a query string or a cookie. A malformed key is refused before any database call; a key that does not check out (unknown, wrong secret, revoked, expired, or from an address outside `allowed_cidrs`) is 401 `invalid_api_key`.
- The tenant comes from the key, not from the host. Row-level security applies as for any tenant request. A key is checked in two steps: `apikeys.Locator` finds its tenant from the key id alone, then the `TxRunner` opens that tenant's transaction, where the row is read and the secret compared. Without tenancy `apikeys.NoTenancy` puts every key in the one tenant; with tenancy the locator reads a global `api_key_tenants (key_id, tenant_id)` table (no secrets, no personal data, no row-level security), written in the transaction that creates the key ([tenancy.md](tenancy.md#api-keys)).
- Rate limits by key (`APP_RATE_API_KEY`, class `api-key`) and by tenant across all its keys (`APP_RATE_API_TENANT`, class `api-tenant`), on top of the operation's own class. Every answer, not only a 429, carries a `RateLimit-Policy` and `RateLimit` entry for each of those classes, so plugins can back off before they are stopped.
- Every write is audited with the key as actor (`apikey` and its id).

### Lifecycle
- Rotation: create the new key, update the plugin, revoke the old one. Keys can carry an expiry; a job tells the tenant's key managers 14 days and 1 day before (`apikeys.DueForReminder(ctx, tx, within)` per window, then `apikeys.MarkReminded` only once a delivery was queued, so a reminder no one received is tried again the next day).
- Security notices (a leaked key, an expiring key, a disabled webhook endpoint) go through `Deps.AdminNotifier` (`app.AdminNotice{Perm, Kind, Fields}`, queued in the event's transaction). With the mail part it defaults to mail to every holder of the permission; without it, production refuses to start with API keys or outbound webhooks on until the app passes one, and outside production a notice with no notifier is logged as undelivered.
- Revocation is immediate on every replica: the key row is read on every request (one indexed read; D34), so no cache can serve a revoked, expired or rescoped key.
- `app apikey:list|create|revoke` from the shell; tenant admins manage their own in the app (`GET`, `POST /api-keys`, `DELETE /api-keys/{keyId}`).
- Leaked-key reports revoke the key, record where it was found (`apikey.leaked` in the audit log) and call the app's `OnLeak` hook to notify the tenant. The delivery id is recorded (`webhook.Verifier.Seen`) in the transaction that revokes, so a replayed delivery gets the same answer and changes nothing; the revoke is conditional, so of two reports racing on one key only the one that revokes it audits `apikey.leaked` and alerts, and a report of a key already revoked is audited once as `apikey.leak_reported` with no alert. With tenancy, leak reports and expiry reminders cross tenants, so they run on the operator pool (the report endpoint's transaction is an operator one, made in `internal/app`; reminders are an operator-pool job), never as a loosened policy. `POST /webhooks/api-key-leaks` takes a JSON array of `{token, type, url, source}`, shaped on GitHub's secret scanning partner alerts but signed with Standard Webhooks secrets (`APP_APIKEY_LEAK_SECRETS`; off without them), and answers `{data: {results: [{tokenHash, label}]}}` with `true_positive` or `false_positive`. A GitHub partner integration needs a small relay or adapter for GitHub's ECDSA signature and bare-array answer.

## 2. The api realm (public API)

- A third realm beside `tenant` and `operator`: own host, bearer keys only, no cookies, no CSRF check (no ambient credentials), CORS off.
- Hosts come from `APP_REALM_API_HOSTS`; without them the realm is not served. Paths are under `/v1`.
- An operation is exposed on the `api` realm only when it is marked `httpx.Public(since)` (a date). It keeps its own realm and is registered on `api` as well, with the same handler, `Need` and rate class (`httpx.Mirror`). The public surface is a deliberate, versioned subset; internal operations stay free to change. keel exposes `GET /v1/ping` and `GET /v1/me` (a key sees its own kind and scopes).
- The `api` realm publishes its own OpenAPI document (`/openapi.json` and `/openapi.yaml` on the api host, served whatever `APP_HTTP_DOCS` says, since plugin developers generate clients from it; `app openapi --realm api` prints it). The document declares an HTTP bearer scheme (`apiKey`) and attaches it to every operation whose `Need` is not public, so generated clients send the key. `keel check` runs `oasdiff breaking --fail-on WARN` against `spec/api.openapi.yaml` at the latest release tag with no exceptions, and skips with a message until a tag has one; a breaking change means a new version path.
- Responses use the same envelope and errors as every other operation ([conventions/api.md](conventions/api.md#response-shape)).
- Idempotency: plugins retry, so every public `POST` that creates something (answers 201) must be marked `idempotency.Required`; the startup check refuses one that is not.
- Deprecation: `httpx.Public(since, httpx.Sunset(deprecatedOn, sunset))` sends `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) headers and marks the operation deprecated in the document; the startup check refuses less than six months' notice and a deprecation date still to come, so add `Sunset` in the release where deprecation starts.

When third-party developers (not the app's own team) build apps that many tenants install, add an OAuth 2.1 authorization server so tenants grant access without copying keys. Keys come first because the first integrations are the app's own plugins.
<!-- /part:apikeys -->

<!-- part:webhooks -->
## 3. Outbound webhooks

- `webhook_endpoints` (tenant-scoped): URL, subscribed event types, secret (shown once), status, failure count.
- Events are recorded in the transaction that caused them (the webhooks service's `Emit(ctx, tx, "order.paid", payload)`), then delivered by jobs, so a rolled-back change never sends an event.
- Payloads carry ids and a small snapshot; receivers fetch the full record through the API if they need it.
- Signed with Standard Webhooks headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`); receivers verify with any Standard Webhooks library.
- Retries with exponential backoff over about three days; a delivery that spends its last attempt disables the endpoint once it has failed `APP_WEBHOOKS_OUT_DISABLE_AFTER` attempts in a row, and the tenant's admins are told (the admin notifier, mail by default). Events and deliveries are kept for `APP_WEBHOOKS_OUT_RETAIN` (30 days) and can be replayed from the app.
- SSRF protection (`kit/netguard`): `https` only in production; the URL's host is resolved and every address must be globally reachable (default deny, see [security.md](security.md#5-request-protections)), then the connection is pinned to the checked address (no second DNS lookup); no redirects; `APP_WEBHOOKS_OUT_TIMEOUT` (10 seconds); response body read capped at 64 KiB.
<!-- /part:webhooks -->

<!-- part:connections -->
## 4. Connections (calling other services as the tenant)

- `connections` (tenant-scoped): provider, external account id, scopes, status, access and refresh tokens encrypted at rest (AES-GCM with keys from `APP_CONNECTION_KEYS`, newest first), token expiry.
- OAuth 2.0 authorization code flow with PKCE through `x/oauth2`; `state` server-side and single use, like sign-in.
- Token refresh takes a lease on the row first, in its own short transaction, because many providers rotate refresh tokens: two workers refreshing at once would leave one holding a dead token and disconnect the tenant. The provider call runs outside any transaction and outside the caller's cancellation; the new tokens are stored conditioned on the lease and version, retrying only the write.
- A provider is an app-side adapter implementing `connections.Provider` (auth URLs, scopes, API origins, revoke). Calls go through an `http.Client` that sends the token only to the provider's declared origins, over the SSRF-safe dialer, with timeouts, retries on 429 and 5xx with backoff, and errors and logs that never include tokens or provider response bodies.
- Disconnect waits for a refresh in flight, revokes the newest tokens at the provider when it supports revocation, then deletes the row.
- Sync work runs as jobs per tenant and per connection, with the connection's own rate limits respected.
<!-- /part:connections -->
