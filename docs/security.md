# Security

What keel protects against, how, and what each app must still do. Every control here has a test; a change that weakens one needs a decision recorded in [decisions.md](decisions.md).

## 1. Production profile

`APP_ENV=staging` or `production` turns on a profile. The binary refuses to start, listing every problem at once, when:

- the public URL is not `https://`;
- cookies are not `Secure` (forced on in production) or the session cookie lacks the `__Host-` prefix;
- a database URL does not verify TLS (`sslmode=verify-full` on Postgres; `tls=true`, or `APP_DATABASE_CA_FILE` with no `tls`, on MySQL), loopback included;
- dev login is enabled (it is refused outside `APP_ENV=local` anyway, and so is `db:seed`);
- any secret is shorter than 32 bytes or still has its example value;
- the Cloudflare proxy edge mode is set without trusted proxies, or the tunnel mode without the tunnel address (the address cloudflared connects from, as the app or nginx sees it; nginx on the same host is listed in trusted proxies);
- the docs and spec routes are enabled (the `api` realm's own `/openapi.json` is public by design and always served).
- a realm with MFA `optional` or `required` has no `APP_MFA_KEYS`, or the operator realm's MFA is not `required`;
- with tenancy: the app pool's role is a superuser, can bypass row-level security or owns the tables (checked against `pg_roles` and `pg_tables` at startup, in every environment), a pool acts as another role than its URL logs in as, the operator pool is missing, cannot bypass row-level security or uses the app pool's role, or the operator URL names the app URL's user.
- a Postgres app or operator URL whose startup parameters set `role`, `session_authorization` or an `app.*` setting (refused by configuration and by `db.Open`), or, with tenancy, a pool opened without the per-checkout tenant reset.

Secrets come from env or from `<NAME>_FILE` (for systemd credentials and Docker secrets). The `config.Secret` type prints as `[redacted]` in logs, errors and `%v`.

## 2. Authentication

### Sessions
- Opaque token: 32 bytes from `crypto/rand`, sent in a cookie, stored only as SHA-256. A database leak does not yield live sessions.
- Cookie: `__Host-` prefix in production, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`.
- Expiry: idle (default 2 h) and absolute (default 12 h). Touch is throttled (once a minute) so reads do not write on every request.
- Rotation: sign-in deletes the session the request arrived with and creates a new one in the same transaction (no session fixation). Passing the second factor rotates too. A change to the user's access (section 3) rotates a browser session on its next request: a new cookie, and the old token stops working; a bearer session keeps its token, since its client has no way to learn a new one. "View as" (tenancy) will rotate as well.
- Sign-in needs a role: a user who holds no role in the realm gets the same answer as a wrong password.
- Revocation: disabling a user, removing their last role in a realm, a password reset, enabling a second factor (every other session), or ten wrong second-factor codes in a row revokes their sessions at once.
- Bearer tokens for non-browser clients use the same table and hashing with a separate kind; they are never accepted from a cookie and never from a query string.

### Realms
Sessions belong to a realm (D17): typically `tenant` and `operator`. Each realm has its own host, cookie name, expiry, MFA policy and permission catalogue. A session from one realm is never accepted on another realm's host, and the operator realm is the only one given the database pool that crosses tenants.

### Passwords (when the password provider is kept)
- argon2id, PHC string format. Parameters are configuration; the default is OWASP's m=19 MiB, t=2, p=1 (D20), chosen so a burst of sign-ins does not exhaust a small host. The RFC 9106 profile (m=64 MiB, t=3, p=4) is available for larger hosts.
- Verify bounds the stored parameters relative to the configured ones: memory at most four times the configured (and at most 256 MiB unless the configured is higher), time at most twice plus one, at most four lanes. A row outside them fails verification with a logged error, so a tampered row cannot exhaust memory. Startup refuses argon2 memory times `APP_PASSWORD_MAX_CONCURRENT` above `APP_PASSWORD_MEMORY_BUDGET`.
- A semaphore caps concurrent hashes; excess sign-ins wait briefly, then get 429. No database connection is held while a sign-in waits for its counter or a hash, and argon2id never runs inside a transaction: the user and hash are read in a short read, verified with nothing held, and only the closing write (rehash, session) opens a transaction.
- Passwords are normalised to NFKC before hashing (NIST SP 800-63B-4), so the same password typed on two keyboards matches; legacy bcrypt hashes are tried with the input as typed, then normalised.
- `NeedsRehash` upgrades parameters on next successful sign-in. Legacy bcrypt hashes (ported apps) verify and are rehashed to argon2id on success.
- Attempt limiter: by account and IP together, and by IP alone; stored in the database so it holds across replicas and deploys (D31); it never lets a third party lock an account out globally. Every attempt is counted before the password is checked, by the same statement that returns the count, so a concurrent burst cannot pass a limit; a success clears the account's count and gives the attempt back to the address. With an unknown client address (an untrusted unix socket peer) the account-and-address count is skipped rather than shared by every such caller.
- Length follows NIST SP 800-63B-4 (final, August 2025): at least 15 characters when the password is the only factor, at least 8 when the realm requires a second factor; at least 64 allowed (keel allows 128 characters and 512 bytes, in the API schema and the service alike). Length and the embedded list of common and breached passwords apply to the normalised form. No composition rules, no forced periodic changes.
- The same response and similar timing for every failure: unknown account, disabled account, no password, wrong password, a password over the maximum, a legacy or out-of-bounds hash. Each runs one argon2id verification at the configured cost.

### Reset, verification and invite tokens
- 32 random bytes in the link, SHA-256 stored, bound to one purpose and one user, single use, 60-minute default expiry (invites longer, configurable). One live token per user and purpose: issuing replaces the row, so only the latest link works, even when two are issued at once.
- Consumed in the same transaction as the change they authorise. A password reset revokes all the user's sessions.
- The link is handed to the notifier inside the transaction that issues it; the notifier enqueues delivery (a mail job) and does no network I/O, so nothing is sent for a rolled-back change. Outside `APP_ENV=local` the server refuses to start without one; locally, links go to the log. `user:create --print-link` prints an invite to the operator's terminal instead.
- Request endpoints answer the same way, after at least 250 ms, whether or not the account exists, and count every request in the database by address and by target account.

### Second factors
- Realm policy: `off`, `optional`, or `required` (the operator realm should be `required`).
- TOTP (RFC 6238, 30-second step, one step of skew): the secret is encrypted at rest with a key from config (key list for rotation); enrolment needs a confirming code; the last used step is stored so a code cannot be replayed; ten recovery codes, shown once, stored hashed, each single use.
<!-- part:passkey -->
- Passkeys (optional part): WebAuthn through go-webauthn, challenges server-side, single use and five minutes, spent before the answer is checked; registration needs a full session and, like any new authenticator, ends the user's other sessions; user verification required for passwordless sign-in, which therefore counts as both factors; a sign count that does not move forward is logged and refused. A passkey works only on the realm it was registered on, so one added where MFA is off never passes another realm's MFA. The signed-in user lists, renames and removes their own passkeys (full session); removing one ends their other sessions and is refused when it is the last second factor of a realm that requires one.
<!-- /part:passkey -->
- A session that passed the first factor but not the second is a restricted session that can only complete MFA or sign out. It carries the user's identity and no grants, `/me` shows only that the second factor is required, and it lives ten minutes. Completing MFA rotates the session; confirming a new authenticator also ends the user's other sessions.
- Code attempts are counted before they are checked, by user and by user and address. Ten wrong codes in a row (a right one clears the run) revoke every session of the user, audited as `mfa.failure_limit_reached`; only someone who has the password can cause it.
- Sensitive actions (changing email, password or MFA, managing access) can require a recent MFA step-up, set per operation.

<!-- part:apikeys -->
### API keys
Tenant-scoped keys for plugins and integrations: secret-scanner-friendly format with a checksum checked before any database call, 256-bit secret stored as SHA-256 and compared in constant time, scopes limited to API-grantable permissions and to what the creator holds, bearer only on the `api` host (no cookies, so no CSRF check and no CORS there), per-key and per-tenant rate limits, audit as the key, optional expiry and IP allowlist, revocation on the next request on every replica (the key row is read per request), leaked-key reports from a signed partner endpoint. Design in [integrations.md](integrations.md#1-api-keys).
<!-- /part:apikeys -->

### Device tokens
For shared devices such as registers or kiosks: a manager (`devices.manage`) creates a short pairing code for the realm, the device exchanges it for a `device_id.secret` bearer token (hash stored), each request looks it up, and rotation keeps the previous secret valid for a grace window of at most 24 hours. Redemption is counted by address in the database before the code is looked up. A device token carries the device's scope, not a person's; the person signs in on top of it when the app needs to know who acted.

<!-- part:oidc -->
### OIDC and OAuth sign-in
- Authorization code flow with PKCE S256.
- `state` and `nonce` are random and stored server-side hashed (`oauth_states`) with the PKCE verifier, which the token request needs in the clear; single use (spent before the code exchange, whatever follows), ten-minute expiry. The state is also set in a `__Host-oidc_state` cookie and the callback must present both, so a callback URL cannot sign another browser in (login CSRF).
- ID token checked for `iss`, `aud` (and `azp` with several audiences), `exp`, `iat` (at most five minutes ahead, ten minutes old) and `nonce` with go-oidc. Userinfo, if used, only adds claims.
- Linking a provider subject to an existing user needs corroboration the app defines (a verified email claim is not enough on its own unless the provider is trusted for it: `APP_OIDC_EMAIL_TRUSTED`). keel has no signed-in "connect a provider" flow, so with `APP_OIDC_EMAIL_TRUSTED=false` and the default Corroborator nobody can link: an app that does not trust the provider's addresses supplies its own. A user who already has an identity from the provider under another subject is refused, so an address the provider reassigns to a new person does not reach the old account. OIDC works only on the realms in `APP_OIDC_REALMS`, and an identity only on the realm it was linked on. OIDC never creates users, and the session starts through `Start`, so a user without a role in the realm is refused and the realm's MFA policy applies.
- No pooled connection is held while the provider is asked anything (discovery, token exchange, keys); a failed discovery is remembered for 30 seconds so a provider that is down fails sign-ins fast instead of queueing them.
- The callback is a GET that starts a session; the state and its cookie are what protect it.
- Return paths go through `httpx.SafeReturnPath` (relative paths only; no `//`, backslashes, control characters, or a scheme).
<!-- /part:oidc -->

### Dev login
Gates: config refuses it outside local and needs `APP_DEV_LOGIN=true` (the Makefile's `dev` sets it) and a loopback listener; each request must come from a loopback client, name a loopback host (`localhost`, a `.localhost` name, `127.0.0.1` or `[::1]`), and carry no forwarding header (`Forwarded`, any `X-Forwarded-*`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, `X-Original-Host`). A tunnel or local proxy in front of the dev server therefore cannot reach it. The route answers 404 when any gate says no.

## 3. Authorisation

- The permission catalogue is a value the app defines in code: code, area, label, description, sensitive flag. Unknown codes in the database are ignored.
- Roles are data (`roles`, `role_permissions`, `user_roles`). A user's permissions are the union of their active roles. Built-in roles belong to the app's code: `setup` creates them and keeps their permissions in step with their definitions (audited as `role.permissions_synced`), and the access API refuses to change or delete one (422 `builtin_role`). An administrator who wants a role without some permission creates a custom role.
- Optional scoped grants: a role given within a scope (for example one branch or one department). `rbac.Scope[K]` supports union, intersect and covers.
- Every operation declares a `Need` in its Huma metadata (`rbac.SignedIn()`, `rbac.Requires(p)`, `rbac.RequiresAny(...)`, `rbac.RequiresIn(p, scopeFrom)`, or `rbac.Public()`). A middleware enforces it before the handler: unmet need is 403. `Requires` and `RequiresAny` count only grants held everywhere; a scoped grant counts only through `RequiresIn`, which reads the scope from the request. An operation with no declaration, hidden ones included, fails the startup check and the operation walk test.
- Services check again with `principal.Can(perm)` or `principal.CanIn(perm, scope)` for contextual rules (owner, assignee, scope). The UI only hides; the server refuses.
- Code checks permissions, never role names.
- Guardrails live in the kit, not in callers: `rbac.Access` (grant, revoke, role permissions, role deletion) and `users.SetStatus` take the acting principal, lock the realm's access state, read the facts inside the transaction and refuse: an actor without the access-management permission where the change applies; editing your own roles; granting a permission you do not hold; a grant across realms; leaving a realm without an active user holding access management everywhere (scoped grants and disabled users do not count) or without a role carrying it, by revoking, editing or deleting a role, or disabling a user. Every access change is audited with before and after and applies on the next request, on every replica: grants, revocations, role permission changes and deletions, status changes and password changes move the user's `access_version` in the same transaction; each request reads it with its session row, a session issued at an older version rotates (section 2), and the short-lived principal cache is keyed by user, realm and version, so an entry filled before a change is never served after it.
- Break-glass: `app user:grant` acts as the system. It skips the checks of what the actor holds, never the realm check, and is audited as the system.

<!-- part:tenancy -->
## 4. Tenant isolation

When the `tenancy` part is kept, the tenant boundary is enforced by Postgres row-level security, not by remembering a `where` clause. Design and rules in [tenancy.md](tenancy.md). The short version:
- The tenant is resolved from host or session, membership is checked, and the tenant is set per transaction (`set_config(..., true)`); an unset tenant sees nothing.
- The app role cannot bypass policies; only the operator realm's pool uses a role that can.
- Unique constraints and foreign keys include `tenant_id`, because constraint checks ignore policies and would otherwise leak existence across tenants.
- Jobs, files, audit and rate limits carry the tenant.
- Tenant and operator transactions are different Go types, and only `kit/db` may write the tenant setting (D29, D30).
- `migrate:validate` refuses any policy other than the tenant policy (unless allowed by name with a reason), a dropped policy or row-level security turned off on a tenant table, and a tenant self-reference without `tenant_id`; a catalogue test over every migration fails the build on what the SQL alone does not show.
<!-- /part:tenancy -->

## 5. Request protections

| Threat | Control |
| --- | --- |
| CSRF | `http.CrossOriginProtection` on all unsafe methods (Sec-Fetch-Site, then Origin vs Host), trusted origins from config. `SameSite=Lax` as a second layer. GET never changes state. |
| CORS abuse | Off by default. When on, an exact origin allowlist; credentials only for listed origins; no wildcard with credentials. |
| Oversized input | `MaxHeaderBytes`; every operation's `MaxBodyBytes` defaults to `APP_HTTP_MAX_BODY_BYTES` and may be set per operation; the same cap on routes outside the API; upload limits per file policy. |
| Slow clients | Read header, read, write and idle timeouts on `http.Server`; per-operation write deadline for downloads. |
| Spoofed client IP | `httpx.ClientAddress` walks `X-Forwarded-For` only through configured trusted proxies, then believes `CF-Connecting-IP` only when the hop where the walk stopped is in Cloudflare's published ranges (or is the tunnel address), and only as a single valid IP. A unix socket peer is a proxy only when trusted with the `unix` token; otherwise its address is unknown, never loopback. No other code reads those headers or `RemoteAddr`. The IP is never used to grant access. |
| Brute force and floods | Token-bucket rate limit on every operation by class (pre-auth by address, then by principal or token); IPv6 aggregated to /64; bounded memory; 429 with `Retry-After` (rounded up) and `RateLimit` headers. A failing store answers 503 on every path unless the class is explicitly fail-open; security counters in the database fail closed. Health probes from this host (loopback, or a trusted proxy on loopback or a trusted unix socket) are not limited. |
| Injection | Jet binds every value as a parameter. Sort keys come from an allowlist mapped to columns. Raw SQL only as constant strings in a store, with bound arguments. No string-built SQL. |
| SSRF (outbound webhooks, connections) | `kit/netguard`, default deny: only public IPv4 unicast and IPv6 in `2000::/3`, outside every IANA special-purpose block that is not globally reachable, plus 6to4, Teredo and NAT64 and the Azure WireServer address; embedded IPv4 judged as IPv4; any zone refused. `https` only, the host resolved once and the connection pinned to the checked address, no proxy from the environment, no redirects (connections: only within the provider's declared API origin, and the token is sent to those origins only), timeouts, capped response reads. |
| Information leaks | Problem responses never echo submitted values (an unknown field's name is cut to 64 characters); 500s say only "internal error" with the request id and drop headers the handler had set; stack traces only in logs; `/livez` reports no build details. Unknown, expired and revoked tokens answer the same 404. |
| Clickjacking and content sniffing | `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on API responses, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, `Strict-Transport-Security` in production. |
| Open redirect | `SafeReturnPath` on every redirect target taken from input. |
| Mass assignment | Input structs per operation; never decode into a database row type. |
| Lost updates | `version` on editable rows; stale write is 409 `stale_version`. |
| Replay of webhooks | Standard Webhooks signature (HMAC-SHA256 over id, timestamp and body) or the timestamped hex scheme (HMAC-SHA256 over timestamp and body, the delivery id from the signed body or a header), five-minute tolerance, several secrets for rotation (at least 24 bytes each in production; one MAC per secret and at most five signatures per request), delivery id stored per sender in the same transaction as its effect. |
| Retried writes | `Idempotency-Key` on marked operations: scoped to the signed-in principal and realm, request hashed with its query and content type, response saved before it is sent, never run twice (a lost outcome is 409 until the key expires). |

<!-- part:files -->
## 6. Files

- Keys are random, never derived from user input: `<APP_FILES_KEY_PREFIX>f/<ab>/<cd>/<32 hex>`. Local storage goes through `os.Root`, so traversal and symlink escapes fail at the OS layer.
- Uploads stream with a size cap to a temporary file, hashed on the way, then fsynced and renamed (both directories synced). Nothing buffers a whole upload in memory. `fileshttp.Upload` reads a raw body or a single multipart file part through `MultipartReader` under the cap, never `ParseMultipartForm`.
- Each upload kind has a policy: allowed types (checked by content, not extension), size, inspection, whether public links may be presigned, and the permission an upload of that kind needs (the upload route answers 403 without it, and the tenant guard refuses uploads into a read-only or suspended tenant).
- Lifecycle: `Put` records a `pending` row with its uploader before the object is written, so every object has a row first. Only the same uploader can `Stage` it and then `Attach` it (a job may attach as the system). `Remove` and `Sweep` delete only keys from rows the package created or keys in its own layout under its prefix; unclaimed pending and staged files expire.
- `files/inspect`:
  - Archives: entry count and directory size from the end records, bound to the directory's position, before archive/zip reads the directory; per-entry ratio; one decoded-bytes budget shared by nested archives. A nested archive is recognised only by `PK\x03\x04` at its start, and PDFs or images inside an archive are not inspected.
  - OOXML: refuses macros (vbaProject parts, macro-enabled and XLM macro sheet content types and relationships), ActiveX, OLE and external relationships (external hyperlinks excepted). Relationship and content-type attributes are read unqualified; a namespaced or repeated `Type`, `Target`, `TargetMode` or `ContentType` is refused.
  - PDF (fails closed): refuses the names `JavaScript`, `JS`, `Launch`, `EmbeddedFile`, `EmbeddedFiles`, `XFA`, `RichMedia`, `GoToR`, `GoToE`, `SubmitForm`, `ImportData` as names in the file's objects and anywhere in decoded stream data (so any `OpenAction` of those types), and encryption. Streams may use only `FlateDecode` (inflated within the budget, PNG and TIFF predictors undone, and every name in the result checked, except an image XObject's pixels, which only spend the budget) and, only on a stream that is exactly an image XObject (no `/N` or `/First`), a final `DCTDecode`, `JPXDecode`, `CCITTFaxDecode` or `JBIG2Decode`, which is not decoded. Refused: any other or abbreviated filter, an indirect `/Filter` or `/DecodeParms`, `/F`, `/DP`, `/FFilter` and `/FDecodeParms` on a stream, a direct `/Length` that does not end at `endstream`, `endstream` inside stream data, an object header or `startxref` inside a string, comment or stream data, and a stream inside decoded data.
  - Images: dimensions, pixels and decoded bytes (pixels times bytes per pixel of the colour model, `APP_FILES_IMAGE_MAX_DECODED_BYTES`) are checked from the header before decoding. PNG and JPEG are re-encoded to strip metadata, and a re-encode larger than the policy's cap is refused. GIF (screen size, and frames times pixels from a block walk) and WebP (canvas and animation frames) are checked but kept as uploaded, metadata included.
  - Text must be valid UTF-8 without NUL. An antivirus hook (ClamAV) is optional.
- Downloads: `fileshttp` answers with `Content-Disposition: attachment` and an RFC 6266 filename, `nosniff`, `Content-Security-Policy: sandbox`, permission checked per file. Signed public links are HMAC-SHA256 over id, tenant and expiry, the first session key signs and all verify, expiry at most seven days. Under tenancy a link serves only on the shared host or its own tenant's host, and only while that tenant is not suspended; otherwise it answers 404, like a missing file. `fileshttp.Public` panics at wiring without its `Admit` callback, which makes that decision before the link's tenant is set. S3 presigned links set the disposition and the stored type but cannot carry `nosniff` or a CSP, so they are used only for policies that set `Presign`; `PublicURL` presigns only a key of the context's tenant, as `Open` reads only one.
<!-- /part:files -->

## 7. Data protection

- TLS to the database in production (verified).
- Database user without superuser or DDL rights at runtime; migrations run as a separate owner role where the host allows it.
- Personal data is not logged: emails, tokens, codes, secrets, request bodies. `logx` redacts known keys; reviewers check new log lines.
- Audit log: append-only, in the same transaction as the change, before and after images with secret fields removed (tags apply even inside types with their own marshalling; other custom marshallers are recorded as `[opaque]`), optional hash chain (each row carries the hash of the previous; a locked head row keeps it from forking) for tamper evidence. Postgres enforces append-only in the migration; MySQL cannot, so the operator grants the app user only SELECT and INSERT on `audit_log`; nothing checks that grant. The chain detects edits and a deleted tail, not a full rewrite by someone who can write both tables.
- Mail and job payloads with personal data are cleared after send by the retention job.
- Backups are the operator's job; [operations.md](operations.md#backups) lists what to back up and how to test a restore.

## 8. Supply chain

- Dependencies are few and listed with reasons in [stack.md](stack.md). A new one needs a reason there.
- Tools are pinned in `go.mod` (`tool` directives) and run with `go tool`. No `curl | sh` in CI.
- `govulncheck` in `make check`; Dependabot (`.github/dependabot.yml`) proposes weekly bumps for Go modules, tools, actions and images.
- Container images pinned by version (digest in production deploys).
- Release builds (`make build`, the Dockerfile) use `-trimpath` and stamped build info; `make build` writes a checksum beside the binary.

## 9. Secrets

- Never in git. `.env` is ignored; `.env.example` holds placeholders that the production profile refuses.
- Rotation: signing keys (`APP_SESSION_KEYS`, for cursors and signed values), MFA keys and webhook secrets accept a list (newest first) so they rotate without downtime. An OIDC client secret is one value: providers that rotate keep the old one valid while the new one is deployed.
- Encryption keys at rest (`APP_CONNECTION_KEYS`, `APP_WEBHOOKS_OUT_KEYS`, `APP_MFA_KEYS`) rotate in four steps:
  1. Put the new key first in the list and keep the old ones after it; deploy. New values are sealed with the new key, and a value opened with an older key is sealed again with the newest the next time it is written (a token refresh, a reconnect, a delivery, an MFA use).
  2. Run `app connection:rekey` and `app webhook:rekey`. They reseal every remaining row in batches and report how many values no configured key opens.
  3. When both report nothing unreadable, remove the old key and deploy.
  4. A value no key opens means a key was removed too early: the connection must be authorised again, the endpoint given a new secret.
- If a secret is committed, rotate it first, then purge history.

## 10. Threat model summary

| Actor | Can | Stopped by |
| --- | --- | --- |
| Anonymous internet | Reach public routes | Rate limits, CSRF check, input limits, uniform errors |
| Signed-in user | Call any operation | `Need` middleware, service checks, scopes, guardrails, audit |
| User of another tenant | Guess ids, craft requests | Row-level security, membership check, tenant-scoped keys, uniform 404 |
| Holder of a stolen password | Sign in | Second factor where the realm requires it, throttling, reset revokes sessions |
| Holder of a stolen cookie | Act as the user until expiry | Idle expiry, revoke-all, `__Host-` and `HttpOnly`, re-auth for sensitive actions (app choice) |
| Webhook sender | Post events | Signature, tolerance, replay store |
| Holder of a leaked API key | Call the public API as that tenant | Scopes, per-key rate limits, secret-scanner revocation, expiry, IP allowlist, audit |
| Tenant registering a webhook URL | Make the server call internal addresses | SSRF dialer |
| Malicious file uploader | Upload content | Policies, inspect, sandboxed download |
| Operator with DB read access | Read data | Hashed tokens and passwords; secrets not in DB |
| Compromised dependency | Run code | Minimal deps, govulncheck, pinned tools, review on bumps |

## 11. Checklist for a new endpoint

- [ ] `Need` declared; service checks contextual rules.
- [ ] Tenant table (if any) has RLS, forced, a policy, and tenant-scoped keys.
- [ ] Rate-limit class declared.
- [ ] Input struct with bounds (`maxLength`, `minimum`, `maxItems`), `MaxBodyBytes` if larger than default.
- [ ] Writes in one transaction with `audit.Record`.
- [ ] Editable resource carries `version`.
- [ ] Errors mapped to stable codes; no input echoed.
- [ ] No personal data in logs.
- [ ] Tests: allowed, refused (403), invalid (422), and the rule it enforces.
