# Operations

How an app made from keel is built, deployed, migrated, observed, backed up and upgraded.

## Local development

```
make up          # the database and Mailpit on 127.0.0.1 (COMPOSE_PROFILES adds pdf and s3)
make seed   # local: migrate, setup, seed
make dev         # run the API
make gen         # Jet schema types + OpenAPI after any migration or endpoint change
make check       # lint, vuln, tests, generated-code drift, API compatibility; must pass before a PR
```

Ports are set in `.env` (`KEEL_*_PORT`) so several apps can run side by side.

## Build

- `make build` writes `bin/app` and `bin/app.sha256` and refuses an empty `BUILD_TIME` (it defaults to now): `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X .../buildinfo.version=$VERSION -X .../buildinfo.commit=$COMMIT -X .../buildinfo.buildTime=$BUILD_TIME"`. Build releases in CI the same way; `release.sh` checks `<binary>.sha256` when it sits next to the binary, and requires it with `REQUIRE_CHECKSUM=1`.
- Container image: `docker build -f deploy/docker/Dockerfile --build-arg VERSION=v1.2.3 --build-arg COMMIT=$(git rev-parse HEAD) --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t registry.example.com/app:v1.2.3 .` from the repo root; the build fails without `BUILD_TIME`, since `.dockerignore` keeps `.git` out and nothing else stamps it (`.dockerignore` keeps docs, deploy files, keys and secrets out of the context). Multi-stage: the Go toolchain go.mod names runs on the builder's platform and cross-compiles for `TARGETOS`/`TARGETARCH` (multi-arch builds need no emulation), with the same flags, into a distroless static `nonroot` final stage with no shell; both base images are pinned by digest. The image sets `APP_HTTP_ADDR=0.0.0.0:8080`, runs `serve` by default, and has no `HEALTHCHECK` (no shell or curl): the orchestrator probes `/readyz` and `/livez`. Push it and deploy it by digest (`image@sha256:...`), never by tag: a tag can point at other bytes on another host.
- Two deploy shapes are shipped in `deploy/`: systemd slots on a VM, and containers (Docker on a host, or Kubernetes). Pick one per app.
- Building on the production host is supported for small VMs but not preferred: it needs the toolchain on the server and makes the build unreproducible.

## Zero-downtime deploys

Every deploy shape keeps serving while it changes version (decision D32). Old and new versions run side by side for a short time, so this rests on three things: expand-and-contract migrations (next sections), sessions and security counters in the database (they survive the switch), and the server's drain sequence (readiness off, a short delay so the proxy stops sending, then a graceful shutdown that finishes in-flight requests).

**Timing.** A stopping slot keeps accepting for `APP_HTTP_SHUTDOWN_DRAIN`, then waits for in-flight requests until drain plus `APP_HTTP_SHUTDOWN_TIMEOUT` has passed, and cuts what is left. A request may run for `APP_HTTP_WRITE_TIMEOUT`, so drain plus shutdown must be at least the write timeout: the app refuses a configuration that does not meet it (its defaults are 5s plus 30s against 30s), and `release.sh` refuses to run when `app.env` does not. The shipped `deploy/systemd/app.env` and `deploy/k8s/configmap.yaml` allow 60s requests with `APP_HTTP_SHUTDOWN_TIMEOUT=60s`. The systemd unit leaves the stop to the app (`TimeoutStopSec=infinity`), Docker's stop timeout is drain plus shutdown plus 10 seconds, and Kubernetes' grace period is the preStop sleep plus drain plus shutdown plus a margin (85s).

**Single host (systemd): blue and green slots.** `deploy/release.sh <binary>`, run as root:
1. Refuse an unsafe configuration: the timing rule above, a duration it cannot read (it reads Go durations such as `5s`, `1m30s` or `1.5s`, and nothing else), or a slot address outside `127.0.0.0/8` and `[::1]` (both slots on different ports).
2. Take the lock `/run/app-release.lock` (`flock`; where there is no `flock`, a symlink naming the holder's pid, taken over when that process is gone), so two releases cannot overlap.
3. Read the state file `/var/lib/app/deploy/state` (root, 0700 directory): the phase, the committed live slot, the candidate, and per slot the release it holds (the binary's sha256, or the image digest) and whether that release was ever live. The live slot comes from here, never from `upstream.conf`. If an earlier run stopped part way, finish or undo it first (below). The target is the slot that is not live, blue on the first release.
4. Copy the binary to `/srv/app/releases/<UTC timestamp>/app`; run `app migrate:validate`, then `app migrate` with the new binary (expand-only changes, so the running version is unaffected). Both run as the `app` user through `systemd-run --wait --pipe --collect` with the unit's sandbox, `app.env`, and for `migrate` only the `database_migrate_url` credential.
5. Record the target as the candidate, stop it if it runs, point `/srv/app/slots/<slot>` at the new release, and `systemctl start app@<slot>`.
6. Poll the slot's `/readyz` until it answers 200, for up to `READY_TIMEOUT` seconds. If it never does, or anything before the switch fails, the script stops the new slot and exits 1: nginx is untouched and the live slot never stopped serving.
7. Write `upstream.conf` to a temporary file and rename it into place, run `nginx -t` and `nginx -s reload`, then poll nginx's loopback verification server (`127.0.0.1:8079`, in the shipped site file) until a fresh request through nginx reaches the new slot, for up to `VERIFY_TIMEOUT` seconds. A reload only signals nginx, so this is what proves the new configuration is in force. If any step fails, the script writes `upstream.conf` for the live slot again, reloads, checks that nginx routes to the live slot, and only then stops the new slot (exit 1). If it cannot confirm that, it leaves both slots running and exits 4.
8. Commit: the state file now names the new slot as live and its release as one that was live. Everything after this is cleanup and can be rerun: `systemctl enable app@<new>` and `disable app@<old>` (only the live slot starts at boot), wait `SWITCH_SETTLE` seconds for nginx's old workers, then `systemctl stop app@<old>`. The old slot turns readiness off, waits the drain delay, finishes in-flight requests, stops its job workers (their jobs return to the queue without spending an attempt), and exits; `systemctl stop` returns when it has. Last, delete all but the newest four releases (the live one and the previous three), never one a slot points at. A failure here exits 3, "deployed, cleanup failed": the release is live, and the next run finishes the cleanup before anything else.

If the script dies part way (a crash, a lost SSH session, `kill -9`), the next run reconciles from the state file before it does anything else: before the switch it stops the candidate; during the switch it puts nginx back on the committed live slot as in step 7; after the commit it finishes the cleanup. Exit codes: 0 done, 1 failed with the live slot unchanged, 2 usage, 3 deployed but cleanup failed, 4 a failed switch could not be confirmed undone (fix nginx, then rerun).

`release.sh rollback` switches back to the other slot only when the release it holds was live before (the state file records it, and the slot must still hold that exact binary): start it, wait for `/readyz`, switch and verify, commit, stop the current slot. After a failed release the other slot holds a build that never went live, so `rollback` refuses it; deploy the release you want instead. Two rollbacks in a row switch back and forth between the last two live releases.

**Docker on a host, behind nginx.** `release.sh --docker <image@sha256:...>` and `release.sh --docker rollback` run the same sequence with two containers, `app-blue` and `app-green`, each publishing its slot's port from `blue.env` or `green.env` on that loopback address (inside, the app listens on 0.0.0.0:8080). The image must be given by digest; the script pulls it unless present, records the digest as the slot's release, and `rollback` checks the stopped container still runs that digest. Migrations run as throwaway containers of the same image. Containers run as `CONTAINER_USER` (`65532:65532`, the image's `nonroot`) with `--read-only`, `--cap-drop ALL`, `no-new-privileges` and `--env-file /etc/app/app.env`. Credentials stay root's in `/etc/app/credentials`: for each container the script stages the ones it needs into `/var/lib/app/deploy/credentials/<slot>` (or `migrate`), a 0500 directory of 0400 files owned by `CONTAINER_USER`, mounts only that directory read-only at `/run/credentials`, and removes it when the slot stops; `database_migrate_url` reaches only the migration container. The live container gets `--restart unless-stopped`, the stopped one `--restart no`, so a reboot brings back the live slot with its staged credentials. The database must be reachable from the Docker bridge: a `127.0.0.1` URL in a credential points at the container itself. nginx's connections reach the app from the Docker bridge gateway (172.17.0.1 by default), so list that address in `APP_PROXY_TRUSTED`. `/tmp` is a tmpfs, so anything the app spools there uses memory.

**Containers (Kubernetes or similar): rolling update.** `deploy/k8s/deployment.yaml`: image by digest, `maxUnavailable: 0`, `maxSurge: 1`, readiness probe on `/readyz` (`timeoutSeconds: 3`, `failureThreshold: 3`, so one slow probe does not eject a pod), liveness on `/livez`, a `preStop` sleep of 10 seconds (longer than the load balancer takes to deregister a pod; a `sleep` action, Kubernetes 1.30 or later, because the image has no shell), `terminationGracePeriodSeconds: 85` (preStop plus drain plus shutdown plus margin), non-root, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, `GOMEMLIMIT=460MiB` (about 90% of the 512Mi limit; change the two together), secrets as files through `*_FILE`. `migrate-job.yaml` runs `migrate:validate` then `migrate` with the owner role, the same digest, bounded resources and a 30-minute deadline; apply it and wait for it to complete before changing the Deployment's digest, and name it per release. `configmap.yaml` trusts only a placeholder range for the ingress controller's pods (`APP_PROXY_TRUSTED`; set it to the controller's own range, never the whole pod network) and `networkpolicy.yaml` lets only the ingress controller (namespace and labels to adjust) reach the pods. `service.yaml` and `pdb.yaml` (`minAvailable: 1`) complete the set; the `app` Secret (`database_url`, `database_operator_url`, `database_migrate_url`, `session_keys`, `smtp_password`) is created outside git. Plain YAML, no Helm.

**What the app guarantees:** on SIGTERM `/readyz` fails at once; new connections are still accepted during the drain delay; `Shutdown` then waits for in-flight requests until drain plus `APP_HTTP_SHUTDOWN_TIMEOUT`; job leases are released, not abandoned. `serve` refuses to start against a schema that is behind the binary, and only warns when the schema is ahead (an older binary during a deploy or rollback is expected to run against newer, expand-only schema).

## Deploy files

| Path | What |
| --- | --- |
| `deploy/systemd/app@.service` | Template unit, one instance per slot (`app@blue`, `app@green`) |
| `deploy/systemd/app.env`, `blue.env`, `green.env` | Starting points for `/etc/app/`, with timing that passes `release.sh`'s check and the SMTP settings production needs (mail is the notifier) |
| `deploy/nginx/nginx.conf` | Site file for nginx's http context: the TLS site and the loopback verification server; includes `upstream.conf` |
| `deploy/nginx/upstream.conf` | The upstream block, in the shape `release.sh` writes; install it before the first release |
| `deploy/release.sh` | Blue and green releases and rollback, systemd or `--docker` |
| `deploy/docker/Dockerfile` | The container image |
| `deploy/k8s/` | Deployment, Service, PodDisruptionBudget, ConfigMap, NetworkPolicy, migration Job |
| `deploy/db/postgres-roles.sql` | Owner, app and (with tenancy) operator database roles |
| `deploy/db/local-init.sh` | Local compose only: runs `postgres-roles.sql` with throwaway passwords at first start |
| `deploy/test/` | The zero-failure switch test (`make deploy-test`) and its never-ready release |

Host layout for the systemd shape:

```
/srv/app/releases/<timestamp>/app   one directory per release
/srv/app/slots/{blue,green}         symlinks to the release each slot runs
/etc/app/app.env                    settings both slots share, no secrets
/etc/app/{blue,green}.env           APP_HTTP_ADDR=127.0.0.1:8081 and 127.0.0.1:8082
/etc/app/credentials/<name>         database_url, database_operator_url, session_keys, smtp_password, database_migrate_url (root, 0600)
/etc/nginx/app/upstream.conf        written by release.sh
/var/lib/app/deploy/state           release.sh's record of the live slot and each slot's release (root only)
/var/lib/app/files                  the files root, the only writable path (StateDirectory=app/files)
```

- `app@.service`: runs as the dedicated `app` user; `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, the `Protect*` kernel, clock, hostname and `ProtectProc=invisible` settings, `RestrictNamespaces`, `RestrictSUIDSGID`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute`, `UMask=0077`, and `StateDirectory=app/files` as the only writable path. `MemoryHigh=704M` and `MemoryMax=768M` per slot with `GOMEMLIMIT=690MiB` (about 90% of `MemoryMax`; change them together). Both slots run during a switch, so the host needs at least 2 GiB: two slots at their limit plus nginx and the system. `TimeoutStopSec=infinity`, since the app bounds its own stop. `ExecStartPre=app migrate:validate`, then the schema check in `serve` itself. Settings come from `EnvironmentFile=/etc/app/app.env` and `/etc/app/%i.env` (the slot's address); secrets from `LoadCredential=` as `APP_DATABASE_URL_FILE=%d/database_url`, `APP_DATABASE_OPERATOR_URL_FILE=%d/database_operator_url` and `APP_SESSION_KEYS_FILE=%d/session_keys` and `APP_MAIL_SMTP_PASSWORD_FILE=%d/smtp_password` (add a pair of lines per further secret). Env files are plain `KEY=value` lines without quotes, since the same file feeds systemd, `docker --env-file` and `release.sh`. `release.sh` enables only the live slot, so do not enable a slot by hand.
- Roles: `deploy/db/postgres-roles.sql` creates the owner and app database roles. `migrate` runs with `APP_DATABASE_MIGRATE_URL` (owner); `serve` and `worker` with `APP_DATABASE_URL` (app), which must log in as another user.
<!-- part:tenancy -->
- With tenancy the script also creates the operator login (it bypasses row-level security, so it needs `-v operator_password=...`), with the rights in [tenancy.md](tenancy.md#3-database-roles); `serve` and `worker` use it through `APP_DATABASE_OPERATOR_URL`, which must log in as a third user. An app made `--without tenancy` has neither the login nor its grants.
<!-- /part:tenancy -->
- `nginx.conf`: `server_tokens off`; an HTTP-to-HTTPS redirect (308, so a POST stays a POST, to the configured name rather than the client's `Host`) and a TLS server with HTTP/2 and Mozilla's intermediate ciphers; HTTP/1.1 keepalive to the upstream (32 idle connections, closed by nginx after 60s, below `APP_HTTP_IDLE_TIMEOUT`, so nginx never sends on a connection the app is closing); `proxy_next_upstream error timeout`, and nginx never retries a POST, LOCK or PATCH it has sent (no `non_idempotent`); with one server in the upstream the only retry is a request whose cached keepalive connection turned out dead. `client_max_body_size 1m` matches `APP_HTTP_MAX_BODY_BYTES`; `location ^~ /api/v1/files/` covers the upload route (`POST /api/v1/files/{kind}`, mounted once the app defines an upload kind) with a 50m limit. nginx buffers that body to disk before it forwards it, so a slow client never holds the app's `APP_HTTP_READ_TIMEOUT`; keep `client_body_temp_path` on a filesystem with room for the concurrent uploads. The verification server listens on `127.0.0.1:8079` only, proxies `/readyz` to the same upstream, and returns the slot it reached in `X-Upstream`. Real-IP directives are present but commented: the app reads `X-Forwarded-For` itself, so enable them only for nginx's own logs behind a load balancer or CDN.
- nginx headers: it sends `X-Forwarded-For $proxy_add_x_forwarded_for` and overwrites `X-Request-Id` with `$request_id`; list nginx's address in `APP_PROXY_TRUSTED` (the app keeps a request id only from a trusted proxy). Behind Cloudflare's proxy, `APP_PROXY_EDGE=cloudflare` with nginx trusted is enough: the walk stops at Cloudflare's address and `CF-Connecting-IP` is believed there. With cloudflared on the same host, trusting `127.0.0.1/32` lets the walk reach the address Cloudflare wrote (see [configuration.md](configuration.md#proxy-and-client-ip)).
- A reload makes nginx's old workers close idle client keepalive connections. A client that sends on one at that moment sees the connection close before any answer; browsers resend in that case, and Go's client does only for idempotent methods.
- `release.sh` settings, all environment variables: `DEPLOY_NAME` (`app`), `DEPLOY_USER` (`$DEPLOY_NAME`), `ENV_PREFIX` (`APP_`), `DEPLOY_ROOT` (`/srv/app`), `ENV_DIR` (`/etc/app`), `CRED_DIR` (`$ENV_DIR/credentials`), `STATE_DIR` (`/var/lib/app/deploy`), `STAGE_DIR` (`$STATE_DIR/credentials`), `UPSTREAM_CONF` (`/etc/nginx/app/upstream.conf`), `UPSTREAM_HOST` (the host nginx dials; the slot's own address by default; when set, the verification compares only the port), `VERIFY_ADDR` (`127.0.0.1:8079`), `LOCK_FILE` (`/run/app-release.lock`), `KEEP_RELEASES` (`3`), `READY_TIMEOUT` (`60`), `VERIFY_TIMEOUT` (`15`), `SWITCH_SETTLE` (`2`), `REQUIRE_CHECKSUM` (`0`), `CONTAINER_PORT` (`8080`), `CONTAINER_USER` (`65532:65532`), and the commands it runs: `SYSTEMCTL`, `SYSTEMD_RUN`, `NGINX`, `DOCKER`, `CURL`, `FLOCK`. A command may be several words, such as `NGINX="docker exec web nginx"`; it is split on whitespace without shell quoting, so a path or argument with a space in it cannot be given. Drain, shutdown and write timeouts are read from `app.env`.
- First release: install `deploy/nginx/upstream.conf` (it names blue on 127.0.0.1:8081; match it to `blue.env`), enable the site and start nginx: `release.sh` verifies the switch through nginx, so nginx must be running. With no state file the first release goes to blue.
- `make deploy-test` builds the app, creates and drops a throwaway database and two login users on the local Postgres (or `APP_TEST_DATABASE_URL`), runs two slots on loopback ports through a stand-in `systemctl` and `systemd-run` (which refuses to run a migration without `User=`), and puts nginx (`nginx:1.30.6-alpine`, the shipped site reduced to plain HTTP, with the verification server) in front. Under continuous requests (ping, `/readyz`, `/livez` with and without keepalive, and a POST nginx must not retry) it runs a release and a rollback, then a set of failures, each of which must leave the live slot serving and the new slot stopped: an unsafe configuration, a release that listens but never becomes ready, a rollback to a build that was never live, `nginx -t` failing, `nginx -s reload` failing, a reload that exits 0 without applying, a crash right after the rename followed by a run that reconciles it, two releases at once, a failed migration, and a checksum mismatch. Two more cases: a request held open (the `deploytest` build tag adds `GET /api/v1/deploytest/hold`, which answers two seconds after its slot was told to stop) must be answered while its slot retires during a release; and a release whose `app.env` is the production profile (https public URL, mail over SMTP as the notifier, signing keys, database URLs with `sslmode=verify-full` through a TLS proxy with a throwaway CA) must start and go live. It fails on any 5xx, connection error or non-2xx GET. With `DEPLOYTEST_DOCKER=1` it also runs `--docker` releases and a rollback by digest through a throwaway registry, checking the staged credentials and restart policies. It needs Docker, takes about 65 seconds (the Docker case about 25 more), and runs on demand and nightly with the Docker case (`.github/workflows/deploy-test.yml`), never in `make test` or PR CI.

## Migrations in deploys

Migrations run before the new binary starts and the old binary keeps serving meanwhile, so every migration must be safe for the old code (expand and contract):

`migrate:validate` enforces this: a migration that drops anything (except `drop index concurrently`), truncates, renames, changes a column type, drops a default, adds `not null`, adds a foreign key or check without `not valid` (Postgres), or creates an index without `concurrently` on Postgres fails validation unless a `-- keel:contract` line comes before `-- +goose Up`. Statements are split the way goose runs them, including several on one line. A contract migration ships only in a release after every running binary has stopped using what it removes.

1. **Expand**: add nullable columns, new tables, new indexes. Old code ignores them.
2. **Deploy code** that writes both old and new shapes, reads the new.
3. **Backfill** in a job or a separate migration in batches.
4. **Contract** in a later release: drop old columns, add `not null`.

Rules:
- Never rename or drop a column the running release reads.
- Postgres: create indexes on large tables with `create index concurrently` in a file marked `-- +goose NO TRANSACTION`.
- MySQL: one statement per file (DDL is not transactional); large table changes use `algorithm=instant` or `inplace` where possible; check with `migrate:validate`.
- `migrate:down` exists for local work only and is refused in production and staging. Fix forward.

### Recovering a failed migration

`release.sh` stops before the switch when `migrate` fails, and the running release keeps serving. A migration in a transaction leaves nothing behind. One marked `-- +goose NO TRANSACTION` can: a `create index concurrently` that fails (a deadlock, a duplicate in a unique index, a cancelled statement) leaves an invalid index that still slows writes, goose does not mark the migration applied, and rerunning it fails because the index exists. Keep one statement in each such file so a failure leaves at most one thing to clean up. To recover on Postgres, as the owner role:

```sql
-- invalid indexes
select n.nspname as schema, c.relname as index
from pg_index i
join pg_class c on c.oid = i.indexrelid
join pg_namespace n on n.oid = c.relnamespace
where not i.indisvalid;

drop index concurrently <schema>.<index>;
```

Then fix the cause and run the release again. On MySQL each file holds one statement and DDL is atomic, so a failed file applied nothing: fix the cause and rerun.

## Maintenance

The queue runs these on its own (global kinds; under tenancy on the operator pool, so one run covers every tenant). `schedule:list` shows them and `schedule:run <name>` runs one now.

| Schedule | When (UTC) | Does |
| --- | --- | --- |
| `jobs.prune` | hourly at :17 | Finished jobs past `APP_JOBS_RETAIN_DONE` and `APP_JOBS_RETAIN_FAILED`, and payloads of kinds with `RetainPayload` |
| `auth.prune` | hourly at :07 | Expired sessions, tokens, passkey challenges, OAuth states, inbound webhook ids (30 days) and rate counters |
| `idempotency.prune` | hourly at :27 | Idempotency keys past `APP_IDEMPOTENCY_TTL` |
| `paging.prune_tombstones` | daily 03:37 | Tombstones past `APP_FEED_TOMBSTONE_RETENTION` |

<!-- part:mail -->
- `mail.prune` (daily 03:41): Outbox rows past `APP_MAIL_RETAIN_LOG`.
<!-- /part:mail -->
<!-- part:webhooks -->
- `webhooks.prune` (daily 04:23): Outbound events and deliveries past `APP_WEBHOOKS_OUT_RETAIN` (with outbound webhooks).
<!-- /part:webhooks -->
<!-- part:files -->
- `files.sweep` (daily 02:47): Files nobody attached within a day, and objects without a row older than a day (with files).
<!-- /part:files -->
<!-- part:apikeys -->
- `apikeys.expiry_reminders` (daily 08:00): Queues one `apikeys.expiry_reminder` job per tenant, which tells its key managers (the admin notifier) about keys that expire within 14 days, then within a day.
<!-- /part:apikeys -->

A schedule's spec, location and kind are stored with the build that wrote them (its build time); during a deploy the older build leaves a schedule the newer one changed, and every process follows the stored spec.

## Observability

- Logs: JSON on stdout to journald or the container runtime. Every line from a request carries `request_id`; search by it from an error response.
- Health: point the load balancer or uptime check at `/readyz`; `/livez` for process supervisors.
<!-- part:otel -->
- OpenTelemetry: set `APP_OTEL_ENDPOINT` to an OTLP collector. Useful first dashboards: request rate, error rate and p95 per route; job queue depth and oldest job age per lane; job failures per kind; database pool wait time.
<!-- /part:otel -->
- Alerts worth having on day one: `/readyz` failing, 5xx rate above baseline, oldest queued job older than ten minutes, disk above 80 percent on the files volume.

## Backups

- Database: managed backups where the host provides them, plus a nightly logical dump (`pg_dump -Fc` or `mysqldump --single-transaction`) copied off the host and kept 30 days.
- Files: bucket versioning on S3, or a nightly sync of the files root.
- Test a restore every quarter into a scratch environment, run `app migrate:status` and `/readyz` against it, and record the date in the app's docs.

## Incidents

- Leaked secret: rotate (all secret settings accept a list, newest first), revoke sessions (`app user:revoke-sessions <email>`; a global sign-out is deleting from `sessions`), then purge history.
- Stuck jobs: `app queue:status` shows depth and the oldest job per lane, `app queue:failed` the failures with their last error, and `app doctor` warns on a backed-up lane or a job past its lease; an expired lease is reclaimed automatically; `app queue:retry <id>` and `app queue:cancel <id>` for manual action. A job of a kind no running build knows is put back for 30 seconds at a time (a newer release may bring it) and fails with `unknown_kind` an hour after it was enqueued.
- Bad deploy: `release.sh rollback` switches the proxy back to the release that was live before, with no downtime. Expand-only migrations mean the previous binary still works against the newer schema. Job schedules stay as the newer build wrote them (a schedule changes only for a build at least as new as the one that wrote it, so two releases side by side cannot flip it back and forth); the next release newer than both brings them in step with its code.

## Upgrading kit code

Apps own their copy, so keel improvements travel as diffs:

1. In keel, each change to `internal/kit` is a commit that touches only kit code and its docs, with a changelog line in `CHANGELOG.md`.
2. `keel init` records the keel version the app was made from in `.keel-version` (`git describe --tags`; make apps from a release tag).
3. In the app, `keel upgrade:diff --keel <keel checkout> <new version>` prints keel's diff of `internal/kit` and `cmd/keel` between that version and the new one, leaving out the kit directories of parts the app removed, with keel's module path rewritten to the app's. `git apply --reject` it (a three-way merge cannot help: the app's repository has none of keel's blobs), resolve the rejected hunks, run `make check`, and write the new version into `.keel-version`.
4. If an app had to edit kit code, that edit is either upstreamed to keel or moved out of `internal/kit` into the app.

Kit migrations ship as new files in keel too; copy them with new timestamps in the app if the app's latest migration is newer. A kit migration of a part the app removed is not copied. `keel compat` in the app compares only the app's own release tags, never keel's.
