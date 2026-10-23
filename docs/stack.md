# Stack

Every dependency, why it is here, and the version checked on 2026-10-22. A new dependency is added here with a reason in the same change. Prefer the standard library.

## Runtime

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| Go | 1.27 | everything | `http.CrossOriginProtection`, `os.Root`, `tool` directives, `testing/synctest` |
| github.com/go-chi/chi/v5 | v5.5.0 | httpx | Router and small middleware set; stdlib-compatible |
| github.com/danielgtaylor/huma/v2 | v2.39.1 | httpx, modules | Code-first OpenAPI 3.1, validation, problem+json |
| github.com/jackc/pgx/v5 | v5.11.0 | db (Postgres) | Postgres driver, used through `pgx/v5/stdlib` |
| github.com/go-sql-driver/mysql | v1.10.1 | db (MySQL) | MySQL driver |
| github.com/pressly/goose/v3 | v3.29.0 | migrate | SQL migrations with a provider API and session lockers |
| github.com/go-jet/jet/v2 | v2.16.1 | stores | Type-safe query builder for Postgres and MySQL over `database/sql` (D23) |
| github.com/lib/pq | v1.12.3 | Jet (indirect) | Array types (`pq.StringArray`) in Jet's Postgres package and generated models; its driver registers as `postgres` but keel connects through pgx |
| github.com/caarlos0/env/v11 | v11.4.1 | config | Env parsing with prefixes, defaults and `_FILE` |
| github.com/google/uuid | v1.6.0 | ids | UUIDv7 and v5 |
| golang.org/x/crypto | v0.58.0 | auth/password | argon2id, bcrypt (legacy verify) |
| golang.org/x/sync | v0.24.0 | server, connections | `errgroup`; `singleflight` for one token refresh per connection per process |
| golang.org/x/net | v0.61.0 | auth/realm | `idna`: internationalised realm hosts to punycode |
| golang.org/x/text | v0.43.0 | users, auth/password | `unicode/norm`: NFC for emails so both engines compare them exactly, NFKC for passwords before hashing |
| github.com/adhocore/gronx | v1.20.5 | jobs | Cron expressions for schedules (maintained; robfig/cron has had no release since 2020) |
| golang.org/x/oauth2 | v0.37.0 | auth/oidc, oauthstate, connections (optional) | Code exchange, PKCE, token refresh |
| github.com/bojanz/currency | v1.5.0 | money | ISO 4217 codes, exponents and locale formatting (x/text's currency formatting is not stable) |
| github.com/shopspring/decimal | v1.6.0 | money, paging, csvx, xlsx | Exact decimal math for rates, tax and FX; compare with `Equal`, never `==` or `DeepEqual` |
| github.com/pquerna/otp | v1.5.0 | auth/totp | RFC 6238 codes and provisioning URIs |
| golang.org/x/image | v0.47.0 | files/inspect | WebP header decoding (`webp.DecodeConfig`) so WebP uploads get the same dimension and decoded-size checks as PNG and JPEG; the standard library has no WebP |

Optional parts, removed with them at `keel init`:
<!-- part:oidc -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/coreos/go-oidc/v3 | v3.21.0 | auth/oidc (optional) | ID token verification, discovery |
| github.com/go-jose/go-jose/v4 | v4.1.6 | auth/oidc (optional, through go-oidc) | JWS verification of ID tokens; raised from the v4.1.4 go-oidc asks for to the current release |
<!-- /part:oidc -->
<!-- part:mail -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/wneessen/go-mail | v0.8.1 | mail (optional) | SMTP with STARTTLS policy, auth methods, timeouts; `net/smtp` is frozen |
<!-- /part:mail -->
<!-- part:files -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/aws/aws-sdk-go-v2/service/s3 | v1.114.4 | files/s3 (optional) | S3 client for AWS, DigitalOcean Spaces, Cloudflare R2 and other S3-compatible stores. Replaces minio-go: the MinIO community project went into maintenance mode in late 2025 and no longer ships images |
| github.com/aws/aws-sdk-go-v2/config | v1.33.9 | files/s3 (optional) | Credentials and endpoint configuration for the S3 client |
| github.com/aws/aws-sdk-go-v2 | v1.47.3 | files/s3 (optional) | SDK core (`aws` helpers) the S3 client is built on |
| github.com/aws/aws-sdk-go-v2/credentials | v1.20.9 | files/s3 (optional) | Static keys from configuration for S3-compatible stores |
| github.com/aws/smithy-go | v1.28.6 | files/s3 (optional) | API error codes, so a missing object maps to `files.ErrNotFound` |
<!-- /part:files -->
<!-- part:passkey -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/go-webauthn/webauthn | v0.18.2 | auth/passkey (optional) | WebAuthn; pre-1.0, pinned and upgraded deliberately |
<!-- /part:passkey -->
<!-- part:xlsx -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/xuri/excelize/v2 | pseudo-version from 2026-10-20 (v2.11.1-0.20261020033641-611b222fd8f7) | xlsx (optional) | Excel read and write; needs Go 1.25+; wrapped with size and row limits. Pinned past v2.11.0 for the fixes to GO-2026-6684, 6685, 6688 and 6689 (unbounded rows, recursion and CFB allocation on crafted workbooks); move to the next tagged release |
<!-- /part:xlsx -->
<!-- part:barcode -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| github.com/boombuler/barcode | v1.1.0 | barcode (optional) | QR, Code 128, EAN; skip2/go-qrcode has had no release since 2020 |
<!-- /part:barcode -->
<!-- part:otel -->

| Module | Version | Used by | Why |
| --- | --- | --- | --- |
| go.opentelemetry.io/otel (with otel/trace and otel/metric) | v1.47.0 | otelx (optional) | Traces and metrics API, propagation; checked 2026-10-23 |
| go.opentelemetry.io/otel/sdk, otel/sdk/metric | v1.47.0 | otelx (optional) | Tracer and meter providers, sampling, batching |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp, otlpmetric/otlpmetrichttp | v1.47.0 | otelx (optional) | OTLP over HTTP; the gRPC exporters would add a gRPC client and server stack. The HTTP exporters still link parts of `google.golang.org/grpc` (status codes) and protobuf: about 11 MB on the binary, only with the part kept |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp | v0.72.0 | otelx (optional) | Server spans and request metrics; otelx names them by the chi route pattern |
| github.com/XSAM/otelsql | v0.44.0 | otelx (optional) | Query spans on both engines through `db.Connector`, since kit/db is `database/sql` over pgx and go-sql-driver; it forwards the session reset and validity check that `db.ResetTenant` needs |
<!-- /part:otel -->

Embedded data
- `internal/kit/auth/password/common.txt`: the first 5,000 distinct entries of 8 to 128 printable ASCII characters, lower-cased, from SecLists' `Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt` (MIT, https://github.com/danielmiessler/SecLists), fetched 2026-10-22. New passwords on it are refused.

Not used, on purpose
- No ORM runtime: Jet builds typed queries from generated schema types, with no reflection-driven loading or hidden queries (D23).
- No Redis: see [architecture.md](architecture.md#1-system).
- Standard Webhooks library: still at v0.0.1; the verifier is about 80 lines in `kit/webhook` with the spec's test vectors.
- testcontainers: compose plus per-package databases is faster on a laptop and in CI; revisit if CI runners cannot run compose.

## Tests

| Module | Version | Why |
| --- | --- | --- |
| github.com/stretchr/testify | v1.12.1 | `require` and `assert`; keep to those two packages |

## Tools (`tools/go.mod` tool directives, D13)

| Tool | Version | Why |
| --- | --- | --- |
| github.com/go-jet/jet/v2/cmd/jet | v2.16.1 | Generates table and model types from the migrated schema |
| github.com/golangci/golangci-lint/v2 | v2.15.0 | Lint and format |
| golang.org/x/vuln (govulncheck) | v1.9.0 | Known-vulnerability check |
| github.com/pressly/goose/v3/cmd/goose | v3.29.0 | `goose create` for new migration files with real timestamps |
| github.com/oasdiff/oasdiff | v1.34.1 | Breaking-change check of the api realm's document against `spec/api.openapi.yaml` at the latest release tag |
| golang.org/x/perf/cmd/benchstat | pseudo-version from 2026-10-09 (no tagged releases) | `keel bench`: compares benchmark runs and tells change from noise |

Outside go.mod: [Hurl](https://hurl.dev) 8.x for contract replay when porting (recorded request and response pairs run against the new app); see [porting.md](porting.md#6-parity-and-done).

## Services (docker-compose, local)

<!-- part:postgres -->
- Postgres, `postgres:18.6`: Primary engine option. 18 is the current stable major; 19 is in release candidates (GA planned for late 2026) and joins the CI matrix once released. Apps on a managed host that only offers 17 still work: keel needs nothing newer than 17
<!-- /part:postgres -->
<!-- part:mysql -->
- MySQL, `mysql:9.7.4` (9.7 is LTS since April 2026): Second engine option; 8.4 LTS stays supported in CI until its end of life
<!-- /part:mysql -->
<!-- part:mail -->
- Mailpit, `axllent/mailpit:v1.31.6`: SMTP sink with a web inbox
<!-- /part:mail -->
<!-- part:pdf -->
- Gotenberg, `gotenberg/gotenberg:8.38.1`, Chromium restricted to `file:///tmp/`, JavaScript off: HTML to PDF
<!-- /part:pdf -->
<!-- part:files -->
- SeaweedFS, `chrislusf/seaweedfs:4.48`, `weed server -s3` (compose profile `s3`): S3 contract tests (MinIO no longer publishes images)
<!-- /part:files -->

## Deploy images

| Image | Where | Why |
| --- | --- | --- |
| `golang:1.27.3-alpine` (by digest) | `deploy/docker/Dockerfile` build stage | The toolchain go.mod names |
| `gcr.io/distroless/static-debian13:nonroot` (by digest) | `deploy/docker/Dockerfile` final stage | No shell or package manager, non-root user, CA certificates and tzdata for a static binary |
| `nginx:1.30.6-alpine` | `deploy/test` | The current stable nginx line, for the switch test |
| `registry:3.1.2` | `deploy/test` (with `DEPLOYTEST_DOCKER=1`) | A throwaway local registry, so the `--docker` case deploys by digest |

CI service containers use the major tags (`postgres:17`, `postgres:18`, `mysql:8.4`, `mysql:9.7`); `deploy-test.yml` pins `postgres:18.6`.
