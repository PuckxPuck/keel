# Review: P6 deploy kit (Opus), 2026-10-23

Verdict: **fix-then-ship.** The happy path works and the test proves it for short GETs. Two failure paths leave a host in a state that turns into an outage later. Both fixes are small.

## Verified

- `make deploy-test`: PASS. 16.7s test time, 18.8s wall, 57,907 requests through nginx across a release, a rollback and a never-ready release, with 0 failures. No containers or listeners were left behind. Run on macOS, where `FLOCK=true` and nginx reaches the slots through `host.docker.internal`, so the real `flock` path runs only in Linux CI.
- shellcheck 0.11.0 (koalaman/shellcheck:stable container) on `deploy/release.sh`: clean on defaults. `-o all` adds only style and info items. One of them, SC2312 at :85, is a real bug (S5).
- `go vet -tags deploytest ./deploy/test`: clean. golangci-lint with `--build-tags deploytest`: 15 findings (N10).
- Image digests checked with `docker buildx imagetools inspect`. They match the current registry indexes: golang 1.27.3-alpine (go.mod pins toolchain go1.27.3), distroless static-debian13:nonroot, nginx 1.30.6-alpine.
- Not run: `docker build` of the Dockerfile (I was not authorized to build) and `--docker` mode (the test does not cover it).
- App facts checked against the code: drain 5s and shutdown 20s (`internal/kit/config/parts.go:49-50`). The listener accepts during the drain and then `Shutdown` runs (`internal/kit/server/server.go:112-123`). Idle timeout is 120s, write timeout 60s, read timeout 30s, body limit 1MiB. `<NAME>_FILE` is read generically (`internal/kit/config/config.go:47`). `migrate:validate` takes no config; `migrate` loads the full config. httpx reads only `X-Forwarded-For` (walked from the right), `X-Request-Id` (only from a trusted proxy) and `CF-Connecting-IP` (only at an edge hop). nginx's headers match these.

## Blockers

**B1. A failed `nginx -s reload` leaves `upstream.conf` naming a stopped slot.** `deploy/release.sh:275-281`, `:293-299`.
`mv` puts the new file in place, then `nginx -t` passes and `nginx -s reload` exits non-zero. Causes include nginx not running, a stale pid file, or `docker exec` failing. With `set -e` the script exits while `switched` is still empty, and `on_exit` stops the new slot. The file is never restored, so `upstream.conf` now names that stopped slot.
- The next reload from anywhere, such as a certbot deploy hook, sends all traffic to a dead port.
- The next `release.sh` reads the wrong live slot. `stop_slot "$next"` (:317) then stops the slot that is actually serving.

Fix: wrap the reload with `if ! run "$NGINX" -s reload; then restore_upstream; die ...; fi`. Also record a `rewrote` flag after the `mv`, and have `on_exit` call `restore_upstream` when `rewrote` is set and `switched` is not. That also covers a Ctrl-C between `mv` and reload.

**B2. Systemd slots are never enabled, so the first reboot after a switch is an outage.** `deploy/systemd/app@.service:42-43`, `deploy/release.sh:317-323`, docs/operations.md (no mention of enabling).
Nothing runs `systemctl enable`. If the operator enables only `app@blue`, the obvious move, then once green is live a reboot starts blue while nginx points at green, and every request gets a 502. Docker mode does not have this problem, because `--restart unless-stopped` keeps the running container running.

Fix: after a successful switch, run `"$SYSTEMCTL" enable "$APP_NAME@$new"` and `disable "$APP_NAME@$old"` (in `deploy` and in `rollback`), and add a line on this to operations.md step 6.

## Should-fix

**S1. Rollback after a failed release can promote the unvetted build.** `deploy/release.sh:318`, `:330-346`, docs/operations.md:37.
The slot symlink, or the docker container (`run_container` :217-219), is repointed before readiness. After any failure before the switch, the idle slot holds the new build. Examples: `nginx -t` failing because of an unrelated site, Ctrl-C during `wait_ready`, or a `READY_TIMEOUT` that is too short. `rollback` then starts that build, it passes `/readyz`, and it goes live. That is a roll forward to a build that never shipped. The docs say "the readiness gate refuses it", which is only true when the failure was readiness itself.

Fix: at switch time, record the release that was live before (for example `$APP_ROOT/slots/previous`, or the image ref in docker mode). `rollback` should target only that, or refuse when the idle slot does not hold it. Correct the docs either way.

**S2. A reload that "succeeds" but is not applied stops the live slot.** `deploy/release.sh:280-290`.
`nginx -s reload` only signals the master and exits 0. If the master then fails to apply the new config (a cert that cannot be read, a bind error, a file changed after `-t`), nginx keeps the old upstream, and `retire` stops the slot that is still serving.

Fix: confirm the switch before retiring. One option: `upstream.conf` also writes `map "" $app_slot { default <slot>; }`. nginx.conf adds a loopback-only `server { listen 127.0.0.1:<port>; location = /slot { return 200 $app_slot; } }`. `switch_to` then polls it until it reads the new slot, with a timeout. On timeout, restore the file and abort without stopping anything.

**S3. Migrations run as root.** `deploy/release.sh:195-200`.
The new, not yet trusted binary runs `migrate` as root with no sandbox, whereas `serve` runs as `app` under `ProtectSystem=strict`.

Fix: run it through `systemd-run --wait --pipe --collect -p User=app -p LoadCredential=... -p EnvironmentFile=$ENV_DIR/app.env` with the same hardening as the unit. Credentials then stay root 0600.

**S4. The shutdown timeout is shorter than the request timeouts, so in-flight requests on the old slot can be cut.** `internal/kit/config/parts.go:45,50`, `deploy/nginx/nginx.conf:40`, `deploy/systemd/app@.service:28`.
Drain plus shutdown is 25s, but `APP_HTTP_WRITE_TIMEOUT` is 60s and `proxy_read_timeout` is 75s. Any request between 25s and 60s that is still on the old slot when it stops gets cut, which contradicts "finishes in-flight requests".

Fix: either set `APP_HTTP_SHUTDOWN_TIMEOUT` to at least the write timeout (and raise `TimeoutStopSec` and `terminationGracePeriodSeconds` to match), or say in operations.md that requests longer than the shutdown timeout are cut during a release.

**S5. A bad duration silently shortens the stop timeout.** `deploy/release.sh:85`.
`die` inside `$(seconds ...)` in the arguments to `printf` only exits the subshell. For example, `APP_HTTP_SHUTDOWN_DRAIN=0` (Go accepts a unitless 0) yields `$(( + 20 + 10))`, which is 30. `docker run --stop-timeout` and `docker stop --time` then kill the container before it finishes draining. shellcheck SC2312 flags this line.

Fix: assign each `seconds` result to a local on its own line, and accept `0` and `us`/`ns`.

**S6. The upload location contradicts the app's read timeout.** `deploy/nginx/nginx.conf:52-57`.
Because of `proxy_request_buffering off`, the app reads the body at the client's speed. Go's `ReadTimeout` (30s) covers the whole body, so a 50m upload needs about 13 Mbit/s or it fails. During a release, any upload still on the old slot is cut at 25s. The comment "Where the app mounts fileshttp.Upload" is also untrue: nothing mounts it yet.

Fix: drop `proxy_request_buffering off`, so nginx spools to disk and forwards over loopback quickly, or tell operators to raise `APP_HTTP_READ_TIMEOUT`. Use `location ^~ /api/v1/files/` so the prefix does not also match `/api/v1/filesX`.

**S7. The switch test does not prove the hard cases.** `deploy/test/switch_test.go:35`, `:102-117`, `:427-444`.
- Every request is a sub-millisecond idempotent GET. There is no long request in flight across the switch, and no POST. POST is the path nginx never retries on a stale upstream keepalive connection.
- `expectStopped("green")` after the never-ready release (:117) proves nothing. `neverReady` never listens, so the check passes even if `on_exit` failed to stop it.
- `--docker` mode, a failing `nginx -t`, a failing reload (B1), a failing migration and a checksum mismatch are all untested.

Fix:
- Add one worker that sends a POST answering a fixed 4xx (for example sign-in with a bad body), and count only 5xx and connection errors as failures.
- Check the pidfile or the process for the never-ready slot instead of the port.
- Add cheap stub cases: `NGINX` as a script that fails `-t`, and one that fails `-s reload`, each asserting that `upstream.conf` is unchanged and the new slot is stopped.
- Long in-flight requests need either a deliberately slow route or a trickled request body through an unbuffered location. If neither is added, say in operations.md:76 that the test covers short requests only.

**S8. `GOMEMLIMIT` is 100% of the container limit.** `deploy/k8s/deployment.yaml:49-52`.
`resourceFieldRef limits.memory` gives the full limit in bytes, so the GC only pushes back at the OOM line, and non-heap memory gets the pod OOM-killed.

Fix: set an explicit value at about 90% of the limit (`460MiB` for 512Mi). Do not use `divisor: 1Mi`: it yields `512` with no unit, which `GOMEMLIMIT` reads as 512 bytes. Related: `deploy/systemd/app@.service:17` gives each slot 768MiB, but both slots run at once during a switch.

**S9. Trusting `10.0.0.0/8` lets any pod set the client IP.** `deploy/k8s/configmap.yaml:11`.
Any pod in the cluster can write `X-Forwarded-For` and `X-Request-Id`. That defeats the per-IP rate limits and the attempt limiter and poisons logs. Pod CIDRs also vary by distribution (EKS uses VPC addresses, k3s 10.42/16).

Fix: use a placeholder for the ingress controller's own pod CIDR, with a comment to narrow it.

**S10. Readiness ejects a pod on a single slow probe.** `deploy/k8s/deployment.yaml:59-64`.
`failureThreshold: 1` with the default `timeoutSeconds: 1` on a `/readyz` that queries the database means one slow query removes the pod. With 2 replicas, both can drop out together.

Fix: `failureThreshold: 2` and `timeoutSeconds: 2`.

## Nits

- N1 `nginx.conf:37`: `proxy_next_upstream_tries 2` does nothing with one server in the upstream (tries equals the server count). The only retry nginx makes is on a dead cached keepalive connection. Make the comment say that.
- N2 `nginx.conf:9`: the redirect uses the client-supplied `$host`. If this is the default server on port 80, any Host header gets redirected. Use `https://app.example.com$request_uri`.
- N3 `nginx.conf:18-23`: add `server_tokens off;`, and consider an explicit Mozilla-intermediate `ssl_ciphers`.
- N4 `release.sh:16,354`: `/run/lock` is world-writable. Under `protected_regular`, another local user can pre-create the lock file and block releases. Use `/run/$APP_NAME-release.lock`.
- N5 `release.sh:158-168`: a missing `.sha256` is skipped without a log line, and an empty one exits through `set -e` with no message. Log the skip, and offer `REQUIRE_CHECKSUM=1`.
- N6 `release.sh:197`: `migrate:validate` runs with root's full environment, while `migrate` runs under `env -i`. Make them consistent.
- N7 `app@.service:28`: `TimeoutStopSec=40` is fixed, while `release.sh` reads drain and shutdown from `app.env`. Warn when `stop_seconds` exceeds the unit's value. `app@.service:40`: `ReadWritePaths` fails the unit if the directory is missing; `StateDirectory=app/files` would create it.
- N8 `app@.service:32-40`: cheap extra hardening: `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`.
- N9 Docker mode docs (operations.md:39): say the database must be reachable from the bridge, because a `127.0.0.1` DSN in the credentials points at the container itself. Also note that uploads spool into the `/tmp` tmpfs, which is RAM.
- N10 `deploy/test/switch_test.go`: the build tag hides it from `keel check`. Linting with the tag gives 7 forbidigo and 8 gosec findings. Add a `.golangci.yml` path exclusion for `^deploy/test/` and lint with the tag in the deploy-test workflow.
- N11 `migrate-job.yaml:7-9`: no `activeDeadlineSeconds` and no `resources`. A migration stuck on a lock runs forever.
- N12 `deploy-test.yml:20`: `postgres:18` is not pinned to a minor version, and there is no `concurrency` group.
- N13 Dockerfile:3: `FROM --platform=$BUILDPLATFORM` with `GOOS`/`GOARCH` from `TARGETOS`/`TARGETARCH` avoids building under emulation for multi-arch. `.dockerignore`: add `*.pem` and `*.key`.
- N14 Docs: operations.md:76 says "about a minute", but it measured 19s. :29 says "blue on the first release", which is only true when `upstream.conf` is absent; the shipped one says blue, so the first release goes to green. Say that two rollbacks in a row roll forward again, and that nginx must be running for the first release.
