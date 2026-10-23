# Configuration

All configuration is environment variables with the app's prefix (`APP_` in keel; `keel init --env-prefix` renames it). Any variable, every secret included, can instead be read from a file named by `<NAME>_FILE`, which is how secrets arrive under systemd credentials or Docker secrets. Setting both `<NAME>` and `<NAME>_FILE` is an error, and a file is capped at 64 KiB. `.env` is loaded by `make dev` only (which defaults `APP_ENV` to `local`); the binary never reads `.env` and tests never see it.

The binary's own defaults are the safe ones. Local conveniences (dev login, loopback listener) are set by the Makefile, not by defaults.

On startup the binary validates every part and prints all problems at once.

## Core

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | (required) | `local`, `test`, `staging`, `production`. `staging` and `production` turn on the production profile ([security.md](security.md#1-production-profile)). |
| `APP_NAME` | (empty) | Shown in authenticator apps and passkey prompts; optional parts default names to it. Empty means `app`. |
| `APP_PUBLIC_URL` | (required in production) | Base URL clients use: absolute, no credentials, query or fragment; `https://` in production. Used for CSRF trusted origins, links in mail, file links, OIDC redirects. |
| `APP_HTTP_ADDR` | `127.0.0.1:8080` | Listener: `host:port`, or `unix:/absolute/path` for a socket (mode 0660, created in a private directory and linked into place; a leftover socket is removed only when a dial is refused). With nginx on the socket, set `APP_PROXY_TRUSTED=unix`. |
| `APP_HTTP_READ_HEADER_TIMEOUT` | `5s` | Every HTTP timeout must be positive. |
| `APP_HTTP_READ_TIMEOUT` | `30s` | |
| `APP_HTTP_WRITE_TIMEOUT` | `30s` | File downloads extend it to 10 minutes. |
| `APP_HTTP_IDLE_TIMEOUT` | `120s` | |
| `APP_HTTP_MAX_HEADER_BYTES` | `64KiB` | Request header cap (`http.Server.MaxHeaderBytes`), below 2 GiB. |
| `APP_HTTP_MAX_BODY_BYTES` | `1MiB` | Body cap of every operation that does not set its own `MaxBodyBytes` (lower or higher), and of routes outside the API. |
| `APP_HTTP_SHUTDOWN_DRAIN` | `5s` | Time between readiness off and shutdown start; zero or more and shorter than the shutdown timeout. |
| `APP_HTTP_SHUTDOWN_TIMEOUT` | `30s` | Bounds in-flight requests and background workers together; a stop takes at most drain plus this. Drain plus this must be at least `APP_HTTP_WRITE_TIMEOUT`, or a stop would cut requests still within their time. |
| `APP_HTTP_DOCS` | `false` | OpenAPI docs and spec routes; refused in production. |
| `APP_HTTP_CORS_ORIGINS` | (empty) | Exact origins, comma separated, `https` in production. Empty means CORS off. Listed origins are also trusted by the CSRF check, alongside the public URL. |
| `APP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `APP_LOG_FORMAT` | `json` | `json` or `text`; `.env.example` sets `text`. |

## Proxy and client IP

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_PROXY_TRUSTED` | (empty) | CIDRs of proxies in front of the app (for example `127.0.0.1/32` for nginx on the host), comma separated; production refuses a `/0`. The token `unix` trusts a peer on the app's unix socket; nginx over a socket needs it. An untrusted socket peer has no known address. |
| `APP_PROXY_EDGE` | `none` | `none`, `cloudflare` (believe `CF-Connecting-IP` from Cloudflare ranges), `cloudflare-tunnel` (from the tunnel address). `cloudflare` needs `APP_PROXY_TRUSTED` in production. |
| `APP_PROXY_TUNNEL_ADDR` | (empty) | Required with `cloudflare-tunnel` and refused with the other edges. The address cloudflared connects from, as the app or nginx sees it. |

The client address comes from walking `X-Forwarded-For` from the right while the hop is a trusted proxy. The edge rule is applied only to the address where that walk stops: `CF-Connecting-IP` is believed when that address is in Cloudflare's ranges (`cloudflare`) or equals the tunnel address (`cloudflare-tunnel`). With cloudflared, nginx and the app on one host and `127.0.0.1/32` trusted, the walk passes through both local hops and the client is the `X-Forwarded-For` entry Cloudflare wrote; a `CF-Connecting-IP` sent straight to nginx is ignored. An incoming `X-Request-Id` is kept only from a trusted proxy.

## Database

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_DATABASE_URL` | (required to serve; validated as required in production) | `postgres://...` or `mysql://...`; the scheme selects the dialect. Production needs `sslmode=verify-full` (Postgres) or `tls=true` (MySQL; or `APP_DATABASE_CA_FILE` with no `tls`). Secret. |
| `APP_DATABASE_CA_FILE` | (empty) | CA for TLS verification. |
| `APP_DATABASE_MAX_OPEN` | `20` | At least 1. With `APP_JOBS_IN_SERVE`, at least the workers in `APP_JOBS_LANES` plus 4 for requests; without it (`app worker`), the workers plus 2. |
| `APP_DATABASE_MAX_IDLE` | `10` | 0 to `APP_DATABASE_MAX_OPEN`. |
| `APP_DATABASE_CONN_LIFETIME` | `30m` | Jittered by up to 10 percent. |
| `APP_DATABASE_CONN_IDLE_TIME` | `5m` | |
| `APP_DATABASE_STATEMENT_TIMEOUT` | `30s` | This and the two timeouts below must be positive. Postgres `statement_timeout`; MySQL `max_execution_time` for selects. |
| `APP_DATABASE_LOCK_TIMEOUT` | `10s` | Postgres `lock_timeout`; MySQL `innodb_lock_wait_timeout` (whole seconds). |
| `APP_DATABASE_IDLE_TX_TIMEOUT` | `60s` | Postgres `idle_in_transaction_session_timeout`. |
| `APP_TEST_DATABASE_URL` | (set by `keel test`) | Tests only: a Postgres URL for a role that creates databases and roles; tests connect as `<prefix>_app`. |
| `APP_TEST_MYSQL_URL` | (set by `keel test`) | Tests only: a MySQL URL for a user that creates databases. |
| `APP_DATABASE_MIGRATE_URL` | (falls back to `APP_DATABASE_URL`) | The owner role used by `app migrate`, which runs without a statement timeout. Secret. The `migrate` commands read only `APP_ENV`, this, `APP_DATABASE_URL`, `APP_DATABASE_CA_FILE` and `APP_DATABASE_LOCK_TIMEOUT`, so a deploy can hand them the owner's URL alone. In production `migrate` requires it (never the app's URL), and `serve` runs without it; when both are set they must log in as different users. |

<!-- part:tenancy -->
## Tenancy (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_DATABASE_OPERATOR_URL` | (empty) | Tenancy only (required with it in production, refused with MySQL and in a build without the tenancy part): a role with `bypassrls` for the operator realm and cross-tenant jobs, never the app URL's user. Secret. |
| `APP_DATABASE_OPERATOR_MAX_OPEN` | `8` | Size of the operator pool, between 1 and `APP_DATABASE_MAX_OPEN`. Under tenancy job workers claim and run on it, so with an operator URL it must be at least the workers in `APP_JOBS_LANES` plus 2. |
| `APP_TENANCY_HOST_SUFFIX` | (empty) | For subdomain resolution, for example `.example.app`; `acme.example.app` resolves `acme`. |
| `APP_TENANCY_CUSTOM_DOMAINS` | `false` | Resolve hosts through `tenant_domains`. |

Tenancy is on when the app keeps the part (its migrations ship with the binary); these settings, `APP_REALM_OPERATOR_HOSTS` and `APP_DATABASE_OPERATOR_URL` are refused with a MySQL URL. A host under the suffix that names no tenant answers 404 `tenant_not_found`.
<!-- /part:tenancy -->

## Realms

Each realm with sign-in has its own block with the realm name in the prefix, for example `APP_REALM_TENANT_HOSTS`. Keys: `HOSTS` (comma separated; empty means any host not claimed by another realm), `COOKIE`, `IDLE`, `ABSOLUTE` (not negative; empty falls back to the session settings), `MFA` (`off`, `optional`, `required`). Defaults for the `tenant` realm follow the session settings below, with `MFA=off`. Realms must not share a cookie name. A realm with `MFA` `optional` or `required` needs `APP_MFA_KEYS` in every environment.
<!-- part:tenancy -->

The `operator` realm (added with tenancy; block `APP_REALM_OPERATOR_*`, served only on `APP_REALM_OPERATOR_HOSTS`) defaults to `COOKIE=operator_session`, `MFA=required` (production refuses less), `IDLE=30m`, `ABSOLUTE=8h`.
<!-- /part:tenancy -->

## Sessions and sign-in

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_SESSION_COOKIE` | `session` | Letters, digits, `-` and `_`, at most 64, not starting with `__`. Gets the `__Host-` prefix in production. |
| `APP_SESSION_IDLE` | `2h` | |
| `APP_SESSION_ABSOLUTE` | `12h` | |
| `APP_SESSION_KEYS` | (required outside local) | HMAC keys for signed cursors and short-lived signed values: comma separated, newest first (the first signs, all verify), each base64 of at least 32 bytes (`openssl rand -base64 32`). Locally, without it, a random key per process is used. Secret. |
| `APP_PASSWORD_ENABLED` | `true` | |
| `APP_PASSWORD_MAX_CONCURRENT` | `4` | Concurrent argon2id hashes, 1 to 256. |
| `APP_PASSWORD_MEMORY_BUDGET` | `256MiB` | Startup refuses argon2 memory times max concurrent above it. |
| `APP_PASSWORD_MIN_LENGTH` | (derived) | 15 when the realm's MFA is `off` or `optional`, 8 when `required` (NIST SP 800-63B-4). Set to override: 8 to 128. |
| `APP_PASSWORD_ARGON2` | `m=19456,t=2,p=1` | argon2id parameters (memory in KiB). Raise on larger hosts; existing hashes upgrade on next sign-in. Production refuses less than OWASP's minimum (m times t of at least 7168 times 5). |
| `APP_TOKENS_TTL` | `60m` | Reset and verification links; `1m` to `24h`. |
| `APP_TOKENS_INVITE_TTL` | `168h` | Invites; `1h` to `720h`. |
| `APP_MFA_KEYS` | (required when any realm uses MFA) | Keys that encrypt TOTP secrets, newest first, comma separated; at least 32 bytes each in production. Secret. |
| `APP_DEV_LOGIN` | `false` | Makefile sets `true` locally. Refused outside local and on a listener that is not loopback. |

<!-- part:passkey -->
Passkeys:

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_PASSKEY_RP_ID`, `APP_PASSKEY_ORIGINS` | (empty) | Relying party id (a host such as `example.app`) and the exact origins ceremonies run on, comma separated, each on the relying party id; `https`, plain `http` only for `localhost` outside production. Empty id means passkeys are off (their operations answer 404); origins without an id are refused. |
<!-- /part:passkey -->
<!-- part:oidc -->

OIDC sign-in:

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_OIDC_ISSUER`, `APP_OIDC_CLIENT_ID`, `APP_OIDC_CLIENT_SECRET`, `APP_OIDC_SCOPES` | (empty; scopes `openid,email,profile`) | Optional provider; empty issuer means OIDC is off (its operations answer 404). The issuer must be `https` in production and needs a client id and `APP_PUBLIC_URL`; the callback is `APP_PUBLIC_URL` + `/api/v1/auth/oidc/callback`. Scopes must include `openid`. The client secret is a secret, and may be empty for a public client (PKCE). |
| `APP_OIDC_REALMS` | `tenant` | The realms with sign-in that OIDC works on, comma separated; an identity signs in only on the realm it was linked on, and the others answer 404. |
| `APP_OIDC_EMAIL_TRUSTED` | `false` | The provider is trusted for verified addresses: a new subject is linked to the existing user with its address when the token says `email_verified`. Off, an app links through its own `Corroborator`. |
<!-- /part:oidc -->

## Rate limits

Each class has a rate written as `<count>/<period>`, for example `60/1m`: at least 1 per period of `1s` or more. Defaults are generous and meant to be tuned per app.

| Variable | Default |
| --- | --- |
| `APP_RATE_PREAUTH` | `3000/1m` by address |
| `APP_RATE_AUTH` | `30/1m` by address |
| `APP_RATE_API_READ` | `600/1m` by principal |
| `APP_RATE_API_WRITE` | `120/1m` by principal |
| `APP_RATE_HEAVY` | `30/1h` by principal |
| `APP_RATE_WEBHOOK` | `120/1m` by address |
| `APP_RATE_HEALTH` | `6000/1m` by address; probes from this host (loopback, or a trusted proxy on it) are never limited |
| `APP_RATE_MAX_KEYS` | `50000`; at least 1 |

## Idempotency

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_IDEMPOTENCY_TTL` | `24h` | How long a key and its stored answer are kept; at least the lease. |
| `APP_IDEMPOTENCY_LEASE` | `2m` | At least `1s`. How long a claim counts as running; after it a repeat is told the outcome is unknown. Keep it above the write timeout. |
| `APP_IDEMPOTENCY_MAX_STORED_BYTES` | `256KiB` | Larger responses are sent whole but stored without their body (1B to 16MiB). |

## Audit

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_AUDIT_CHAIN` | `false` | Link every audit row to the previous one by hash (tamper evidence). Serialises audit writes on the chain's head row. |

## Jobs

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_JOBS_IN_SERVE` | `true` | Run workers inside `serve`; otherwise run `app worker`. |
| `APP_JOBS_LANES` | `fast:4,slow:1` | Lane name and worker count (1 to 256), at least one lane. |
| `APP_JOBS_LEASE` | `2m` | Renewed every third of the lease; at least `1s`. Leases are compared across hosts, so keep their clocks in sync (NTP); skew adds to the time two workers could overlap. |
| `APP_JOBS_POLL` | `1s` | At most `1m`. |
| `APP_JOBS_MAX_ATTEMPTS` | `8` | 1 to 1000. |
| `APP_JOBS_RETAIN_DONE` | `168h` | Done and cancelled jobs; at least `1h`. |
| `APP_JOBS_RETAIN_FAILED` | `720h` | Failed jobs; at least `1h`. |
| `APP_JOBS_SHUTDOWN_GRACE` | `15s` | Shorter than `APP_HTTP_SHUTDOWN_TIMEOUT`, which bounds workers and requests together. |

<!-- part:mail -->
## Mail (optional)

Mail is the notifier for reset, verification and invite links outside `APP_ENV=local` (locally, with the `log` driver, the links are logged instead), and carries the app's own notices (API key expiry and leaks, a disabled webhook endpoint). `APP_MAIL_DRIVER` (`log` by default, refused in production; `smtp`), `APP_MAIL_FROM` (required with `smtp`; with `log` it defaults to `no-reply@localhost`), `APP_MAIL_SMTP_HOST` (required with `smtp`), `APP_MAIL_SMTP_PORT` (`587`), `APP_MAIL_SMTP_USER`, `APP_MAIL_SMTP_PASSWORD` (secret), `APP_MAIL_SMTP_TLS` (`starttls` by default and required of the server; `tls` for implicit TLS; `none` allowed only to loopback), `APP_MAIL_SMTP_TIMEOUT` (`15s`, at most `5m`), `APP_MAIL_RETAIN_BODY` (`72h`, at least `1h`; message bodies in finished send jobs are cleared after it, and bodies carrying a token as soon as they are sent), `APP_MAIL_RETAIN_LOG` (`720h`, at least the body retention; outbox attempt rows).
<!-- /part:mail -->

<!-- part:files -->
## Files (optional)

`APP_FILES_DRIVER` (empty by default: files are off, and the file routes answer 404; `local`, `s3`), `APP_FILES_ROOT` (absolute, must exist), `APP_FILES_TEMP_DIR` (absolute; uploads are spooled here while checked; the system temporary directory when empty), `APP_FILES_S3_ENDPOINT` (`https` in production; empty means AWS), `APP_FILES_S3_BUCKET` and `APP_FILES_S3_REGION` (required with `s3`), `APP_FILES_S3_ACCESS_KEY` and `APP_FILES_S3_SECRET_KEY` (set together; the secret is a secret of at least 32 bytes in production; without keys the SDK's default chain applies), `APP_FILES_S3_SSE` (`true` by default), `APP_FILES_S3_PATH_STYLE` (`false`; SeaweedFS and some S3-compatible stores need `true`), `APP_FILES_KEY_PREFIX` (empty; key segments ending in `/`, such as `myapp/prod/`, so apps and environments can share a bucket: each sweep lists and deletes only under its own prefix), `APP_FILES_INSPECT_CONCURRENCY` (`2`, at least 1), `APP_FILES_IMAGE_MAX_DECODED_BYTES` (`134217728`, 128 MiB: the memory one image may take decoded). Public links are signed with `APP_SESSION_KEYS` and served under `/api/v1/public-files/{fileId}`; S3 presigns them only for policies that set `Presign`. Upload kinds are code (`filePolicies` in `internal/app/files.go`: each kind's policy and the permission an upload of it needs, which must be in the tenant catalogue), each at `POST /api/v1/files/{kind}`; an upload may take up to ten minutes, beyond `APP_HTTP_READ_TIMEOUT`.
<!-- /part:files -->

<!-- part:xlsx -->
## xlsx (optional)

`APP_XLSX_MAX_BYTES` (`20MiB`), `APP_XLSX_MAX_ROWS` (`100000`), `APP_XLSX_MAX_CELLS` (`2000000`); all positive.
<!-- /part:xlsx -->

<!-- part:pdf -->
## PDF (optional)

`APP_PDF_URL` (absolute http(s)), `APP_PDF_USER` and `APP_PDF_PASSWORD` (set together; the password is a secret of at least 32 bytes in production), `APP_PDF_TIMEOUT` (`30s`), `APP_PDF_MAX_BYTES` (`32MiB`).
<!-- /part:pdf -->

## Change feeds

`APP_FEED_TOMBSTONE_RETENTION` (`720h`, at least `1h`): how long tombstones of deleted rows are kept for change feeds; a feed token older than this resyncs (410 `resync_required`). Pruned daily.

<!-- part:otel -->
## OpenTelemetry (optional)

`APP_OTEL_ENDPOINT` (empty means off): the collector's OTLP/HTTP base URL, such as `http://collector:4318`, without credentials (it is printed; they go in the headers); traces go to `/v1/traces` and metrics to `/v1/metrics` under it. `APP_OTEL_HEADERS` (secret; `key=value` pairs separated by commas, sent with every export, for a vendor's API key), `APP_OTEL_SAMPLE` (`0.1`, 0 to 1: the share of traces kept; an inbound `traceparent` never overrides it, it becomes a link on the request's new trace), `APP_OTEL_SERVICE` (the service name, also the requests' fixed `server.address`; `APP_NAME`, else `app`). Health checks are not traced; spans carry no client address, and failures are recorded by error type or status code, never an error's text. `serve` and `worker` export; both flush for up to five seconds on shutdown. These settings are keel's switch: the standard `OTEL_*` variables are not read for the endpoint or headers, but the exporters still honour the others they define (`OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_TIMEOUT`) once `APP_OTEL_ENDPOINT` turns them on.
<!-- /part:otel -->

<!-- part:apikeys -->
## API keys and the public API (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_REALM_API_HOSTS` | (empty) | Hosts of the public API, for example `api.example.app`. Empty means the `api` realm is not served. |
| `APP_APIKEY_PREFIX` | app name | Prefix in the key format: 2 to 16 lower case letters and digits. Without it, `APP_NAME` lower-cased when it fits, else `app`. |
| `APP_APIKEY_LEAK_SECRETS` | (empty) | Standard Webhooks secrets (`whsec_...`, newest first) of the secret-scanning partner that reports leaked keys; empty turns the report operation off. Secret. |
| `APP_RATE_API_KEY` | `600/1m` | Per key, class `api-key`. |
| `APP_RATE_API_TENANT` | `1200/1m` | Per tenant across its keys, class `api-tenant`. |
<!-- /part:apikeys -->
<!-- part:webhooks -->

## Outbound webhooks (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_WEBHOOKS_OUT_TIMEOUT` | `10s` | Per delivery; `1s` to `1m`. |
| `APP_WEBHOOKS_OUT_ALLOW_HTTP` | `false` | Refused in production. Also lets an endpoint URL name a blocked IP literal at creation (local receivers); the dialer still refuses blocked addresses. |
| `APP_WEBHOOKS_OUT_KEYS` | (empty) | Encrypt endpoint signing secrets, newest first; empty means the connection keys are used, and without either outbound webhooks are off. At least 32 bytes each in production. Secret. |
| `APP_WEBHOOKS_OUT_DISABLE_AFTER` | `10` | At least 1. Consecutive failed attempts after which a delivery that spent its last attempt disables the endpoint. |
| `APP_WEBHOOKS_OUT_RETAIN` | `720h` | Events and their deliveries; at least `24h`. |
| `APP_WEBHOOKS_OUT_SECRET_OVERLAP` | `24h` | After a secret rotation the old secret signs beside the new one this long (0 to `168h`), so a receiver can switch without refusing deliveries. |
<!-- /part:webhooks -->
<!-- part:connections -->

## Connections (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_CONNECTION_KEYS` | (empty) | Encrypt stored provider tokens (AES-256-GCM, keys derived with HKDF), newest first; empty means connections are off. At least 32 bytes each in production. Secret. |
<!-- /part:connections -->

## Webhooks (inbound)

Each sender has its own verifier with its own secrets (`webhook.NewVerifier`): keel's one, the leaked-key report, reads `APP_APIKEY_LEAK_SECRETS`. An app adds a setting per sender it receives from; secrets are newest first: `whsec_...` with at least 24 decoded bytes in production for Standard Webhooks, used as they are with at least 24 bytes for the timestamped hex scheme (`webhook.NewTimestampedVerifier`).
