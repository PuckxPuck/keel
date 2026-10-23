# Deploy kit review (Codex)

Codex session 01a16506-04f7-7e11-87aa-2e39a7dbc00d, read-only. Saved from its final answer.

Found three blockers and several availability/security gaps. No files were modified.

## Blockers

1. [deploy/release.sh:265](deploy/release.sh:265) — The nginx switch is not transactional or crash-safe.

   - Failure: `upstream.conf` is replaced before reload. If `nginx -s reload` exits nonzero, `set -e` reaches the exit trap, which stops the new slot but does not restore the file. Disk now points at a stopped slot.
   - Failure: a crash between the rename and reload leaves nginx serving the old slot while `live_slot` reports the new one. The next deploy can stop the actually-live slot.
   - Failure: a successful `nginx -s reload` invocation only means the signal was sent. The master applies the configuration afterward and may retain the old configuration if application fails; the script nevertheless marks the switch complete and stops the old slot. This follows from nginx’s documented signal/reload behavior. [NGINX control documentation](https://nginx.org/en/docs/control.html), [command switches](https://nginx.org/en/docs/switches.html).
   - Fix: persist an explicit switch phase and committed-live state separately from the candidate config; restore and reload the previous config on every uncommitted failure; reconcile incomplete state at startup; and verify that nginx is actually routing to the target slot before retiring the old one. The verification needs a slot/version-observable response or equivalent acknowledgement.

2. [deploy/k8s/configmap.yaml:8](deploy/k8s/configmap.yaml:8), [internal/app/serve.go:31](internal/app/serve.go:31), [internal/app/build.go:84](internal/app/build.go:84) — The current app cannot start in production.

   - Failure: `serve` opens a database and calls `Build` without a notifier. `Build` refuses every database-backed server whose notifier is nil outside local mode. Kubernetes explicitly sets production, and real systemd/Docker deployments will do likewise, so `/readyz` is never reached.
   - The switch test hides this by setting `APP_ENV=local` at [deploy/test/switch_test.go:255](deploy/test/switch_test.go:255), which installs the log notifier.
   - Fix: an app change is required: wire a production notifier into `serve`, or make the notifier optional while failing only notifier-dependent operations. Add a production-profile startup test to the deploy test.

3. [deploy/release.sh:147](deploy/release.sh:147), [deploy/docker/Dockerfile:21](deploy/docker/Dockerfile:21), [docs/operations.md:65](docs/operations.md:65) — Documented credentials are unreadable in Docker mode.

   - Failure: the host layout specifies root-owned `0600` credential files. Docker bind-mounts those exact inodes, while the image runs as UID 65532. Migration and serve containers therefore fail with permission denied before readiness.
   - Fix: provide a Docker-specific secret staging mechanism owned by UID 65532, or provision files as root:65532 with mode `0440`. Document and test the exact ownership and directory traversal permissions.

## Should-fix

1. [deploy/release.sh:195](deploy/release.sh:195), [docs/operations.md:28](docs/operations.md:28) — A newly supplied application binary is executed directly as root.

   - Failure: both validation and migration execute before systemd’s sandbox applies. A compromised artifact or application vulnerability gets host root, despite the service otherwise using a dedicated user.
   - Fix: run both commands as the app user in a hardened transient systemd unit with only the required migration credential and filesystem access.

2. [deploy/test/switch_test.go:94](deploy/test/switch_test.go:94) — The test misses the failure modes most likely to violate zero downtime.

   - Failure: it tests only successful systemd switches and a pre-switch readiness failure. It does not inject `nginx -t` failure, reload failure, a reload command that succeeds without applying the config, interruption around the rename, concurrent releases, slow in-flight requests, migration failure, or Docker mode.
   - Fix: add fault-injection cases for each switch phase, a long request spanning retirement, a concurrent-lock test, crash/restart reconciliation, and a Docker-mode switch/rollback. Keep load running through every injected failure.

3. [deploy/systemd/app@.service:27](deploy/systemd/app@.service:27), [deploy/release.sh:81](deploy/release.sh:81) — systemd’s stop budget can be shorter than configured drain plus shutdown.

   - Failure: `release.sh` dynamically reads the two settings, but the unit always kills after 40 seconds. Increasing drain/shutdown beyond that cuts requests and workers short.
   - Fix: use an intentionally generous/infinite systemd timeout because the app already has an internal bound, or have release preflight and reject configurations whose sum exceeds `TimeoutStopSec`.

4. [deploy/k8s/configmap.yaml:10](deploy/k8s/configmap.yaml:10), [deploy/k8s/service.yaml:7](deploy/k8s/service.yaml:7) — Kubernetes trusts an excessively broad proxy range.

   - Failure: any workload reaching the ClusterIP from `10.0.0.0/8` can supply spoofed `X-Forwarded-For` and `X-Request-Id`. This corrupts audit attribution and permits bypassing address-based rate limits.
   - Fix: trust only the ingress controller’s actual source range and ship a NetworkPolicy restricting Service ingress to that controller and approved probes.

5. [deploy/release.sh:307](deploy/release.sh:307), [deploy/k8s/deployment.yaml:34](deploy/k8s/deployment.yaml:34), [deploy/k8s/migrate-job.yaml:22](deploy/k8s/migrate-job.yaml:22) — Production application images are not digest-pinned.

   - Failure: Docker skips pulling when a mutable tag already exists, while Kubernetes’ version tags default to `IfNotPresent`. Hosts can therefore deploy different or stale bytes under the same release name.
   - Fix: require `image@sha256:…` in Docker mode and use the same digest in the Deployment and migration Job. Store that digest as release state for rollback.

6. [Makefile:47](Makefile:47) — `make build` fails in a clean checkout.

   - Failure: `/bin/` is ignored and currently absent, but the target writes `bin/app` without creating `bin`.
   - Fix: add `mkdir -p bin` before `go build`, and exercise `make build` in CI.

7. [deploy/release.sh:322](deploy/release.sh:322) — Post-commit failures are reported like failed releases.

   - Failure: after nginx has switched, a failed old-slot stop or prune exits nonzero. An operator rerunning the command can flip back to the other slot and destroy the rollback point even though the first release committed.
   - Fix: explicitly record the commit point, make post-switch cleanup idempotent, distinguish “deployed, cleanup failed” in output/status, and avoid treating pruning as a failed deployment.

8. [deploy/release.sh:195](deploy/release.sh:195), [docs/operations.md:80](docs/operations.md:80) — Non-transactional migration failure has no recovery path.

   - Failure: a failed PostgreSQL `CREATE INDEX CONCURRENTLY` can leave an invalid index. Goose will not mark the migration applied, and rerunning the same create can fail because the relation exists. PostgreSQL explicitly documents this residual state and manual recovery. [PostgreSQL CREATE INDEX documentation](https://www.postgresql.org/docs/current/sql-createindex.html).
   - Fix: document and test recovery using catalogue inspection plus `DROP INDEX CONCURRENTLY`/`REINDEX CONCURRENTLY`; require one Up statement in every `NO TRANSACTION` migration; and print a clear “schema may require repair” diagnostic after migration failure.

9. [deploy/release.sh:105](deploy/release.sh:105) — The claimed loopback validation does not validate loopback.

   - Failure: `0.0.0.0:8081` and arbitrary hostnames pass the regex. In systemd mode this can expose the app directly, bypassing nginx TLS and header normalization.
   - Fix: parse the address and permit only `127.0.0.0/8` or `::1` for host-slot mode.

10. [deploy/systemd/app@.service:17](deploy/systemd/app@.service:17) — Memory planning does not account for both slots running concurrently.

   - Failure: each slot gets `GOMEMLIMIT=768MiB`; during a release both run, so Go heaps alone may target 1.5 GiB, excluding stacks, nginx, and the kernel. On a small VM the deploy can invoke the OOM killer and take out the live slot.
   - Fix: size each slot for overlap, document minimum host memory, and add `MemoryHigh`/`MemoryMax`; `GOMEMLIMIT` is a GC target, not an OS limit.

## Nits

1. [deploy/nginx/nginx.conf:9](deploy/nginx/nginx.conf:9) — Use `308` instead of `301` so clients preserve unsafe methods and request bodies during HTTP-to-HTTPS redirects.

2. [docs/operations.md:72](docs/operations.md:72) — The retry description is broader than nginx’s actual rule. nginx specifically suppresses retrying sent `POST`, `LOCK`, and `PATCH` requests unless `non_idempotent` is enabled; it is not a general semantic-idempotency classifier. The shipped standard-method configuration is otherwise safe. [NGINX proxy documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream).

3. [deploy/release.sh:44](deploy/release.sh:44) — Command overrides are whitespace-split and do not honor shell quoting. Multiword examples work, but executable paths or arguments containing spaces do not. Use separate executable/argument variables or document the restriction.

4. [deploy/k8s/migrate-job.yaml:20](deploy/k8s/migrate-job.yaml:20) — Neither migration container declares resource requests or limits. Add bounded resources so a bad migration cannot create node-wide pressure.

Validation: `bash -n deploy/release.sh` passed. Shellcheck was unavailable. Builds and tests were not run because they create artifacts, caches, databases, processes, and containers, which would violate the requested read-only review. nginx 1.30.6 is the current stable release; the remaining concern is digest pinning, not the selected version. [NGINX downloads](https://nginx.org/en/download.html), [official Docker tag](https://hub.docker.com/_/nginx/tags?name=-alpine&page=1).

Verdict: fix-then-ship.
195,029
Found three blockers and several availability/security gaps. No files were modified.

## Blockers

1. [deploy/release.sh:265](deploy/release.sh:265) — The nginx switch is not transactional or crash-safe.

   - Failure: `upstream.conf` is replaced before reload. If `nginx -s reload` exits nonzero, `set -e` reaches the exit trap, which stops the new slot but does not restore the file. Disk now points at a stopped slot.
   - Failure: a crash between the rename and reload leaves nginx serving the old slot while `live_slot` reports the new one. The next deploy can stop the actually-live slot.
   - Failure: a successful `nginx -s reload` invocation only means the signal was sent. The master applies the configuration afterward and may retain the old configuration if application fails; the script nevertheless marks the switch complete and stops the old slot. This follows from nginx’s documented signal/reload behavior. [NGINX control documentation](https://nginx.org/en/docs/control.html), [command switches](https://nginx.org/en/docs/switches.html).
   - Fix: persist an explicit switch phase and committed-live state separately from the candidate config; restore and reload the previous config on every uncommitted failure; reconcile incomplete state at startup; and verify that nginx is actually routing to the target slot before retiring the old one. The verification needs a slot/version-observable response or equivalent acknowledgement.

2. [deploy/k8s/configmap.yaml:8](deploy/k8s/configmap.yaml:8), [internal/app/serve.go:31](internal/app/serve.go:31), [internal/app/build.go:84](internal/app/build.go:84) — The current app cannot start in production.

   - Failure: `serve` opens a database and calls `Build` without a notifier. `Build` refuses every database-backed server whose notifier is nil outside local mode. Kubernetes explicitly sets production, and real systemd/Docker deployments will do likewise, so `/readyz` is never reached.
   - The switch test hides this by setting `APP_ENV=local` at [deploy/test/switch_test.go:255](deploy/test/switch_test.go:255), which installs the log notifier.
   - Fix: an app change is required: wire a production notifier into `serve`, or make the notifier optional while failing only notifier-dependent operations. Add a production-profile startup test to the deploy test.

3. [deploy/release.sh:147](deploy/release.sh:147), [deploy/docker/Dockerfile:21](deploy/docker/Dockerfile:21), [docs/operations.md:65](docs/operations.md:65) — Documented credentials are unreadable in Docker mode.

   - Failure: the host layout specifies root-owned `0600` credential files. Docker bind-mounts those exact inodes, while the image runs as UID 65532. Migration and serve containers therefore fail with permission denied before readiness.
   - Fix: provide a Docker-specific secret staging mechanism owned by UID 65532, or provision files as root:65532 with mode `0440`. Document and test the exact ownership and directory traversal permissions.

## Should-fix

1. [deploy/release.sh:195](deploy/release.sh:195), [docs/operations.md:28](docs/operations.md:28) — A newly supplied application binary is executed directly as root.

   - Failure: both validation and migration execute before systemd’s sandbox applies. A compromised artifact or application vulnerability gets host root, despite the service otherwise using a dedicated user.
   - Fix: run both commands as the app user in a hardened transient systemd unit with only the required migration credential and filesystem access.

2. [deploy/test/switch_test.go:94](deploy/test/switch_test.go:94) — The test misses the failure modes most likely to violate zero downtime.

   - Failure: it tests only successful systemd switches and a pre-switch readiness failure. It does not inject `nginx -t` failure, reload failure, a reload command that succeeds without applying the config, interruption around the rename, concurrent releases, slow in-flight requests, migration failure, or Docker mode.
   - Fix: add fault-injection cases for each switch phase, a long request spanning retirement, a concurrent-lock test, crash/restart reconciliation, and a Docker-mode switch/rollback. Keep load running through every injected failure.

3. [deploy/systemd/app@.service:27](deploy/systemd/app@.service:27), [deploy/release.sh:81](deploy/release.sh:81) — systemd’s stop budget can be shorter than configured drain plus shutdown.

   - Failure: `release.sh` dynamically reads the two settings, but the unit always kills after 40 seconds. Increasing drain/shutdown beyond that cuts requests and workers short.
   - Fix: use an intentionally generous/infinite systemd timeout because the app already has an internal bound, or have release preflight and reject configurations whose sum exceeds `TimeoutStopSec`.

4. [deploy/k8s/configmap.yaml:10](deploy/k8s/configmap.yaml:10), [deploy/k8s/service.yaml:7](deploy/k8s/service.yaml:7) — Kubernetes trusts an excessively broad proxy range.

   - Failure: any workload reaching the ClusterIP from `10.0.0.0/8` can supply spoofed `X-Forwarded-For` and `X-Request-Id`. This corrupts audit attribution and permits bypassing address-based rate limits.
   - Fix: trust only the ingress controller’s actual source range and ship a NetworkPolicy restricting Service ingress to that controller and approved probes.

5. [deploy/release.sh:307](deploy/release.sh:307), [deploy/k8s/deployment.yaml:34](deploy/k8s/deployment.yaml:34), [deploy/k8s/migrate-job.yaml:22](deploy/k8s/migrate-job.yaml:22) — Production application images are not digest-pinned.

   - Failure: Docker skips pulling when a mutable tag already exists, while Kubernetes’ version tags default to `IfNotPresent`. Hosts can therefore deploy different or stale bytes under the same release name.
   - Fix: require `image@sha256:…` in Docker mode and use the same digest in the Deployment and migration Job. Store that digest as release state for rollback.

6. [Makefile:47](Makefile:47) — `make build` fails in a clean checkout.

   - Failure: `/bin/` is ignored and currently absent, but the target writes `bin/app` without creating `bin`.
   - Fix: add `mkdir -p bin` before `go build`, and exercise `make build` in CI.

7. [deploy/release.sh:322](deploy/release.sh:322) — Post-commit failures are reported like failed releases.

   - Failure: after nginx has switched, a failed old-slot stop or prune exits nonzero. An operator rerunning the command can flip back to the other slot and destroy the rollback point even though the first release committed.
   - Fix: explicitly record the commit point, make post-switch cleanup idempotent, distinguish “deployed, cleanup failed” in output/status, and avoid treating pruning as a failed deployment.

8. [deploy/release.sh:195](deploy/release.sh:195), [docs/operations.md:80](docs/operations.md:80) — Non-transactional migration failure has no recovery path.

   - Failure: a failed PostgreSQL `CREATE INDEX CONCURRENTLY` can leave an invalid index. Goose will not mark the migration applied, and rerunning the same create can fail because the relation exists. PostgreSQL explicitly documents this residual state and manual recovery. [PostgreSQL CREATE INDEX documentation](https://www.postgresql.org/docs/current/sql-createindex.html).
   - Fix: document and test recovery using catalogue inspection plus `DROP INDEX CONCURRENTLY`/`REINDEX CONCURRENTLY`; require one Up statement in every `NO TRANSACTION` migration; and print a clear “schema may require repair” diagnostic after migration failure.

9. [deploy/release.sh:105](deploy/release.sh:105) — The claimed loopback validation does not validate loopback.

   - Failure: `0.0.0.0:8081` and arbitrary hostnames pass the regex. In systemd mode this can expose the app directly, bypassing nginx TLS and header normalization.
   - Fix: parse the address and permit only `127.0.0.0/8` or `::1` for host-slot mode.

10. [deploy/systemd/app@.service:17](deploy/systemd/app@.service:17) — Memory planning does not account for both slots running concurrently.

   - Failure: each slot gets `GOMEMLIMIT=768MiB`; during a release both run, so Go heaps alone may target 1.5 GiB, excluding stacks, nginx, and the kernel. On a small VM the deploy can invoke the OOM killer and take out the live slot.
   - Fix: size each slot for overlap, document minimum host memory, and add `MemoryHigh`/`MemoryMax`; `GOMEMLIMIT` is a GC target, not an OS limit.

## Nits

1. [deploy/nginx/nginx.conf:9](deploy/nginx/nginx.conf:9) — Use `308` instead of `301` so clients preserve unsafe methods and request bodies during HTTP-to-HTTPS redirects.

2. [docs/operations.md:72](docs/operations.md:72) — The retry description is broader than nginx’s actual rule. nginx specifically suppresses retrying sent `POST`, `LOCK`, and `PATCH` requests unless `non_idempotent` is enabled; it is not a general semantic-idempotency classifier. The shipped standard-method configuration is otherwise safe. [NGINX proxy documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream).

3. [deploy/release.sh:44](deploy/release.sh:44) — Command overrides are whitespace-split and do not honor shell quoting. Multiword examples work, but executable paths or arguments containing spaces do not. Use separate executable/argument variables or document the restriction.

4. [deploy/k8s/migrate-job.yaml:20](deploy/k8s/migrate-job.yaml:20) — Neither migration container declares resource requests or limits. Add bounded resources so a bad migration cannot create node-wide pressure.

Validation: `bash -n deploy/release.sh` passed. Shellcheck was unavailable. Builds and tests were not run because they create artifacts, caches, databases, processes, and containers, which would violate the requested read-only review. nginx 1.30.6 is the current stable release; the remaining concern is digest pinning, not the selected version. [NGINX downloads](https://nginx.org/en/download.html), [official Docker tag](https://hub.docker.com/_/nginx/tags?name=-alpine&page=1).

Verdict: fix-then-ship.
