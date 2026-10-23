#!/usr/bin/env bash
# Blue and green release on one host behind nginx (docs/operations.md, D32).
#   release.sh <binary>                    install the binary and switch to it (systemd slots)
#   release.sh rollback                    switch back to the release that was live before
#   release.sh --docker <image@sha256:...> the same with two containers
#   release.sh --docker rollback
# Exit status: 0 done; 1 failed and the live slot is unchanged; 2 usage; 3 deployed but cleanup failed
# (rerun to finish it); 4 a failed switch could not be confirmed undone (fix nginx, then rerun).
set -euo pipefail

DEPLOY_NAME=${DEPLOY_NAME:-app}
DEPLOY_USER=${DEPLOY_USER:-$DEPLOY_NAME}
ENV_PREFIX=${ENV_PREFIX:-APP_}
DEPLOY_ROOT=${DEPLOY_ROOT:-/srv/$DEPLOY_NAME}
ENV_DIR=${ENV_DIR:-/etc/$DEPLOY_NAME}
CRED_DIR=${CRED_DIR:-$ENV_DIR/credentials}
STATE_DIR=${STATE_DIR:-/var/lib/$DEPLOY_NAME/deploy}
STAGE_DIR=${STAGE_DIR:-$STATE_DIR/credentials}
UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/$DEPLOY_NAME/upstream.conf}
UPSTREAM_HOST=${UPSTREAM_HOST:-}
VERIFY_ADDR=${VERIFY_ADDR:-127.0.0.1:8079}
LOCK_FILE=${LOCK_FILE:-/run/$DEPLOY_NAME-release.lock}
KEEP_RELEASES=${KEEP_RELEASES:-3}
READY_TIMEOUT=${READY_TIMEOUT:-60}
VERIFY_TIMEOUT=${VERIFY_TIMEOUT:-15}
SWITCH_SETTLE=${SWITCH_SETTLE:-2}
REQUIRE_CHECKSUM=${REQUIRE_CHECKSUM:-0}
CONTAINER_PORT=${CONTAINER_PORT:-8080}
CONTAINER_USER=${CONTAINER_USER:-65532:65532}
SYSTEMCTL=${SYSTEMCTL:-systemctl}
SYSTEMD_RUN=${SYSTEMD_RUN:-systemd-run}
NGINX=${NGINX:-nginx}
DOCKER=${DOCKER:-docker}
CURL=${CURL:-curl}
FLOCK=${FLOCK:-flock}

STATE_FILE=$STATE_DIR/state
MIGRATE_CRED=database_migrate_url
# The same sandbox as deploy/systemd/app@.service, for migrations run with a new binary.
HARDENING=(
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p PrivateDevices=yes
    -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p SystemCallFilter=@system-service
    -p SystemCallArchitectures=native -p "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
    -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectKernelLogs=yes
    -p ProtectControlGroups=yes -p ProtectClock=yes -p ProtectHostname=yes -p ProtectProc=invisible
    -p RestrictNamespaces=yes -p RestrictSUIDSGID=yes -p RestrictRealtime=yes -p LockPersonality=yes
    -p MemoryDenyWriteExecute=yes -p UMask=0077
)

mode=systemd
lock_link=""
stop_secs=0
addr_blue="" addr_green=""
cred_args=()

st_mode="" st_phase=idle st_live="" st_candidate="" st_retiring=""
st_release_blue="" st_release_green="" st_committed_blue=0 st_committed_green=0

log() { printf '%s release: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
    log "error: $*"
    exit 1
}

usage() {
    printf 'usage: %s [--docker] <binary|image@sha256:...|rollback>\n' "${0##*/}" >&2
    exit 2
}

# run splits an overridable command, such as NGINX="docker exec web nginx", on whitespace.
run() {
    local -a cmd
    read -r -a cmd <<<"$1"
    shift
    "${cmd[@]}" "$@"
}

# crash_point lets the switch test kill the script at a named step, as a power cut would.
crash_point() {
    if [[ ${RELEASE_TEST_CRASH_AT:-} == "$1" ]]; then
        kill -KILL $$
    fi
}

other_slot() {
    if [[ $1 == blue ]]; then printf green; else printf blue; fi
}

env_value() {
    local file=$1 key=$2 line value=""
    [[ -f $file ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        if [[ $line == "$key="* ]]; then
            value=${line#"$key="}
        fi
    done <"$file"
    printf '%s' "$value"
}

# duration_ns reads a Go duration such as 5s, 1m30s or 1.5s and refuses anything else.
duration_ns() {
    local d=$1 rest=$1 total=0 int frac unit mult scale
    local re='^([0-9]+)(\.([0-9]+))?(ns|us|ms|s|m|h)(.*)$'
    if [[ $d == 0 ]]; then
        printf 0
        return 0
    fi
    [[ -n $d ]] || die "empty duration"
    while [[ -n $rest ]]; do
        [[ $rest =~ $re ]] || die "cannot read duration '$d'; write a Go duration such as 5s or 1m30s"
        int=${BASH_REMATCH[1]} frac=${BASH_REMATCH[3]} unit=${BASH_REMATCH[4]} rest=${BASH_REMATCH[5]}
        ((${#int} <= 12)) || die "duration '$d' is too long"
        case $unit in
            ns) mult=1 ;;
            us) mult=1000 ;;
            ms) mult=1000000 ;;
            s) mult=1000000000 ;;
            m) mult=60000000000 ;;
            h) mult=3600000000000 ;;
        esac
        total=$((total + 10#$int * mult))
        if [[ -n $frac ]]; then
            frac=${frac:0:9}
            scale=$((10 ** ${#frac}))
            if ((mult % scale == 0)); then
                total=$((total + 10#$frac * (mult / scale)))
            else
                total=$((total + 10#$frac * mult / scale))
            fi
        fi
    done
    printf '%s' "$total"
}

setting_ns() {
    local value
    value=$(env_value "$ENV_DIR/app.env" "$ENV_PREFIX$1")
    duration_ns "${value:-$2}"
}

# slot_addr reads the slot's listen address and accepts only loopback, so a slot is never reachable
# around nginx.
slot_addr() {
    local addr octets o port re4='^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})$' re6='^\[::1\]:([0-9]{1,5})$'
    addr=$(env_value "$ENV_DIR/$1.env" "${ENV_PREFIX}HTTP_ADDR")
    if [[ $addr =~ $re4 ]]; then
        octets="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
        port=${BASH_REMATCH[4]}
        for o in $octets; do
            ((10#$o <= 255)) || port=0
        done
    elif [[ $addr =~ $re6 ]]; then
        port=${BASH_REMATCH[1]}
    else
        port=0
    fi
    ((10#$port >= 1 && 10#$port <= 65535)) ||
        die "$ENV_DIR/$1.env must set ${ENV_PREFIX}HTTP_ADDR to 127.0.0.0/8 or [::1] with a port, not '$addr'"
    printf '%s' "$addr"
}

preflight() {
    local drain shutdown write
    drain=$(setting_ns HTTP_SHUTDOWN_DRAIN 5s)
    shutdown=$(setting_ns HTTP_SHUTDOWN_TIMEOUT 30s)
    write=$(setting_ns HTTP_WRITE_TIMEOUT 30s)
    ((drain + shutdown >= write)) ||
        die "${ENV_PREFIX}HTTP_SHUTDOWN_DRAIN plus ${ENV_PREFIX}HTTP_SHUTDOWN_TIMEOUT must be at least ${ENV_PREFIX}HTTP_WRITE_TIMEOUT, or a stopping slot cuts requests that are still within their time (set them in $ENV_DIR/app.env)"
    stop_secs=$(((drain + shutdown + 999999999) / 1000000000 + 10))
    addr_blue=$(slot_addr blue)
    addr_green=$(slot_addr green)
    [[ ${addr_blue##*:} != "${addr_green##*:}" ]] || die "blue and green must listen on different ports"
}

addr_of() {
    local var=addr_$1
    printf '%s' "${!var}"
}

# upstream_target is where nginx dials the slot; a container publishes its port on the slot's address.
upstream_target() {
    local addr
    addr=$(addr_of "$1")
    printf '%s:%s' "${UPSTREAM_HOST:-${addr%:*}}" "${addr##*:}"
}

load_state() {
    local key value
    [[ -f $STATE_FILE ]] || return 0
    while IFS='=' read -r key value || [[ -n $key ]]; do
        case $key in
            mode | phase | live | candidate | retiring | release_blue | release_green | committed_blue | committed_green)
                printf -v "st_$key" '%s' "$value"
                ;;
            '') ;;
            *) die "unknown key '$key' in $STATE_FILE" ;;
        esac
    done <"$STATE_FILE"
    [[ -z $st_mode || $st_mode == "$mode" ]] || die "$STATE_FILE belongs to $st_mode mode, not $mode"
}

save_state() {
    local tmp=$STATE_FILE.tmp.$$
    printf 'mode=%s\nphase=%s\nlive=%s\ncandidate=%s\nretiring=%s\nrelease_blue=%s\nrelease_green=%s\ncommitted_blue=%s\ncommitted_green=%s\n' \
        "$mode" "$st_phase" "$st_live" "$st_candidate" "$st_retiring" \
        "$st_release_blue" "$st_release_green" "$st_committed_blue" "$st_committed_green" >"$tmp"
    mv -f "$tmp" "$STATE_FILE"
}

take_lock() {
    local holder
    if command -v "${FLOCK%% *}" >/dev/null 2>&1; then
        exec 9>"$LOCK_FILE"
        run "$FLOCK" -n 9 || die "another release holds $LOCK_FILE"
        return 0
    fi
    # Without flock(1) the lock is a symlink naming the holder's pid; a dead holder's lock is taken over.
    if ! ln -s "$$" "$LOCK_FILE" 2>/dev/null; then
        holder=$(readlink "$LOCK_FILE" 2>/dev/null || true)
        if [[ $holder =~ ^[0-9]+$ ]] && kill -0 "$holder" 2>/dev/null; then
            die "another release (pid $holder) holds $LOCK_FILE"
        fi
        log "taking over the lock left by pid ${holder:-unknown}, which is gone"
        rm -f "$LOCK_FILE"
        ln -s "$$" "$LOCK_FILE" 2>/dev/null || die "another release holds $LOCK_FILE"
    fi
    lock_link=$LOCK_FILE
}

release_lock() {
    if [[ -n $lock_link && $(readlink "$lock_link" 2>/dev/null) == "$$" ]]; then
        rm -f "$lock_link"
    fi
}

cred_var() {
    printf '%s%s_FILE' "$ENV_PREFIX" "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
}

sha256_of() {
    local sum
    if command -v sha256sum >/dev/null; then
        read -r sum _ < <(sha256sum "$1") || true
    else
        read -r sum _ < <(shasum -a 256 "$1") || true
    fi
    [[ -n $sum ]] || die "cannot checksum $1"
    printf '%s' "$sum"
}

verify_checksum() {
    local artifact=$1 expected=""
    if [[ ! -f $artifact.sha256 ]]; then
        [[ $REQUIRE_CHECKSUM != 1 ]] || die "$artifact.sha256 is missing and REQUIRE_CHECKSUM=1"
        log "no $artifact.sha256 next to the binary; installing it unchecked"
        return 0
    fi
    read -r expected _ <"$artifact.sha256" || true
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "$artifact.sha256 does not hold a sha256 checksum"
    [[ $(sha256_of "$artifact") == "$expected" ]] || die "$artifact does not match $artifact.sha256"
}

install_release() {
    local artifact=$1 dir
    [[ -f $artifact && -x $artifact ]] || die "$artifact is not an executable file"
    verify_checksum "$artifact"
    dir=$DEPLOY_ROOT/releases/$(date -u +%Y%m%dT%H%M%SZ)
    [[ ! -e $dir ]] || dir=$dir-$$
    mkdir -p "$DEPLOY_ROOT/releases" "$DEPLOY_ROOT/slots"
    chmod 0755 "$DEPLOY_ROOT/releases" "$DEPLOY_ROOT/slots"
    mkdir -m 0755 "$dir"
    install -m 0755 "$artifact" "$dir/$DEPLOY_NAME"
    printf '%s' "$dir"
}

prune_releases() {
    local keep=$((KEEP_RELEASES + 1)) dirs=() d i blue green
    blue=$(readlink "$DEPLOY_ROOT/slots/blue" 2>/dev/null || true)
    green=$(readlink "$DEPLOY_ROOT/slots/green" 2>/dev/null || true)
    for d in "$DEPLOY_ROOT"/releases/*/; do
        [[ -d $d ]] && dirs+=("${d%/}")
    done
    for ((i = 0; i < ${#dirs[@]} - keep; i++)); do
        d=${dirs[i]}
        [[ $d == "$blue" || $d == "$green" ]] && continue
        rm -rf -- "$d" || return 1
    done
}

migration_failed() {
    die "$1 failed; nothing was switched and ${st_live:-no slot} keeps serving. A failed migration marked -- +goose NO TRANSACTION (create index concurrently) can leave an invalid index behind: see 'Recovering a failed migration' in docs/operations.md before you rerun"
}

# transient runs the new binary as the app user in a sandbox like the unit's, with app.env and the
# given systemd-run arguments.
transient() {
    run "$SYSTEMD_RUN" --wait --pipe --collect --quiet --service-type=exec \
        -p "User=$DEPLOY_USER" -p "Group=$DEPLOY_USER" "${HARDENING[@]}" -p "EnvironmentFile=$ENV_DIR/app.env" "$@"
}

migrate_systemd() {
    local bin=$1
    [[ -f $CRED_DIR/$MIGRATE_CRED ]] || die "$CRED_DIR/$MIGRATE_CRED is missing"
    transient "$bin" migrate:validate || die "migrate:validate refused the release; nothing was changed"
    # %d is not expanded in a transient unit's environment, so the shell reads $CREDENTIALS_DIRECTORY.
    # shellcheck disable=SC2016
    transient -p "LoadCredential=$MIGRATE_CRED:$CRED_DIR/$MIGRATE_CRED" \
        /bin/sh -c 'exec env "$1=$CREDENTIALS_DIRECTORY/$2" "$3" migrate' sh \
        "$(cred_var "$MIGRATE_CRED")" "$MIGRATE_CRED" "$bin" || migration_failed migrate
}

unstage() {
    local dir=$STAGE_DIR/$1
    [[ -e $dir ]] || return 0
    chmod 0700 "$dir"
    rm -rf -- "$dir"
}

# stage copies the credentials a container gets into its own directory owned by the image's user,
# since the originals stay root's; serve never gets the migration credential.
stage() {
    local name=$1 purpose=$2 dir=$STAGE_DIR/$1 f cred
    unstage "$name"
    mkdir -p "$STAGE_DIR"
    chmod 0700 "$STAGE_DIR"
    mkdir -m 0700 "$dir"
    cred_args=()
    for f in "$CRED_DIR"/*; do
        [[ -f $f ]] || continue
        cred=${f##*/}
        if [[ $purpose == migrate && $cred != "$MIGRATE_CRED" ]] || [[ $purpose == serve && $cred == "$MIGRATE_CRED" ]]; then
            continue
        fi
        cp "$f" "$dir/$cred"
        chmod 0400 "$dir/$cred"
        cred_args+=(-e "$(cred_var "$cred")=/run/credentials/$cred")
    done
    chown -R "$CONTAINER_USER" "$dir"
    chmod 0500 "$dir"
    cred_args+=(--mount "type=bind,src=$dir,dst=/run/credentials,readonly")
}

docker_run() {
    run "$DOCKER" run --user "$CONTAINER_USER" --read-only --cap-drop ALL --security-opt no-new-privileges \
        --env-file "$ENV_DIR/app.env" "$@"
}

migrate_docker() {
    local image=$1
    docker_run --rm "$image" migrate:validate || die "migrate:validate refused the release; nothing was changed"
    stage migrate migrate
    if ! docker_run --rm "${cred_args[@]}" "$image" migrate; then
        unstage migrate
        migration_failed migrate
    fi
    unstage migrate
}

container_exists() {
    run "$DOCKER" container inspect "$DEPLOY_NAME-$1" >/dev/null 2>&1
}

run_container() {
    local slot=$1 image=$2 addr
    addr=$(addr_of "$slot")
    if container_exists "$slot"; then
        run "$DOCKER" rm -f "$DEPLOY_NAME-$slot" >/dev/null
    fi
    stage "$slot" serve
    docker_run -d --name "$DEPLOY_NAME-$slot" --restart no --tmpfs /tmp --stop-timeout "$stop_secs" \
        "${cred_args[@]}" -e "${ENV_PREFIX}HTTP_ADDR=0.0.0.0:$CONTAINER_PORT" \
        -p "${addr%:*}:${addr##*:}:$CONTAINER_PORT" "$image" serve >/dev/null
}

start_slot() {
    if [[ $mode == docker ]]; then
        stage "$1" serve
        run "$DOCKER" start "$DEPLOY_NAME-$1" >/dev/null
    else
        run "$SYSTEMCTL" start "$DEPLOY_NAME@$1"
    fi
}

stop_slot() {
    [[ -n $1 ]] || return 0
    if [[ $mode == docker ]]; then
        if container_exists "$1"; then
            run "$DOCKER" stop --time "$stop_secs" "$DEPLOY_NAME-$1" >/dev/null || return 1
        fi
        unstage "$1"
    else
        run "$SYSTEMCTL" stop "$DEPLOY_NAME@$1"
    fi
}

# persist_boot makes only the live slot come back after a reboot.
persist_boot() {
    local live=$1 old=$2
    if [[ $mode == docker ]]; then
        run "$DOCKER" update --restart unless-stopped "$DEPLOY_NAME-$live" >/dev/null || return 1
        if [[ -n $old ]] && container_exists "$old"; then
            run "$DOCKER" update --restart no "$DEPLOY_NAME-$old" >/dev/null || return 1
        fi
    else
        run "$SYSTEMCTL" --quiet enable "$DEPLOY_NAME@$live" || return 1
        if [[ -n $old ]]; then
            run "$SYSTEMCTL" --quiet disable "$DEPLOY_NAME@$old" || return 1
        fi
    fi
}

slot_holds() {
    local slot=$1 release=$2
    if [[ $mode == docker ]]; then
        [[ $(run "$DOCKER" container inspect -f '{{.Config.Image}}' "$DEPLOY_NAME-$slot" 2>/dev/null) == "$release" ]]
    else
        [[ -f $DEPLOY_ROOT/slots/$slot/$DEPLOY_NAME && $(sha256_of "$DEPLOY_ROOT/slots/$slot/$DEPLOY_NAME") == "$release" ]]
    fi
}

wait_ready() {
    local url deadline=$((SECONDS + READY_TIMEOUT))
    url="http://$(addr_of "$1")/readyz"
    until run "$CURL" -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; do
        ((SECONDS < deadline)) || die "$1 was not ready within ${READY_TIMEOUT}s"
        sleep 0.5
    done
}

# routed_to prints the slot address nginx's loopback verification server proxied a 200 /readyz to.
routed_to() {
    local line status="" upstream=""
    while IFS= read -r line; do
        line=${line%$'\r'}
        case $line in
            HTTP/*)
                status=${line#* }
                status=${status%% *}
                ;;
            [Xx]-[Uu]pstream:*)
                upstream=${line#*:}
                upstream=${upstream# }
                ;;
        esac
    done < <(run "$CURL" -sS -o /dev/null -D - --max-time 2 "http://$VERIFY_ADDR/readyz" 2>/dev/null || true)
    [[ $status == 200 && -n $upstream ]] || return 1
    printf '%s' "$upstream"
}

# verify_route waits until fresh connections through nginx reach slot. With UPSTREAM_HOST set nginx
# shows the resolved address, so only the port is compared.
verify_route() {
    local target got deadline=$((SECONDS + VERIFY_TIMEOUT))
    target=$(upstream_target "$1")
    while :; do
        if got=$(routed_to); then
            if [[ $got == "$target" || (-n $UPSTREAM_HOST && $got == *":${target##*:}") ]]; then
                return 0
            fi
        fi
        ((SECONDS < deadline)) || return 1
        sleep 0.5
    done
}

write_upstream() {
    local tmp=$UPSTREAM_CONF.tmp.$$
    # keepalive_timeout stays below APP_HTTP_IDLE_TIMEOUT so nginx, not the app, closes idle connections.
    printf '# slot: %s\nupstream %s {\n    server %s;\n    keepalive 32;\n    keepalive_timeout 60s;\n}\n' \
        "$1" "$DEPLOY_NAME" "$(upstream_target "$1")" >"$tmp"
    mv -f "$tmp" "$UPSTREAM_CONF"
}

restore_upstream() {
    if [[ -n $st_live ]]; then
        write_upstream "$st_live"
        rm -f "$UPSTREAM_CONF.prev"
    elif [[ -f $UPSTREAM_CONF.prev ]]; then
        mv -f "$UPSTREAM_CONF.prev" "$UPSTREAM_CONF"
    else
        rm -f "$UPSTREAM_CONF"
    fi
}

begin() {
    st_phase=prepared st_candidate=$1
    save_state
}

switch_to() {
    local slot=$1
    st_phase=switching
    save_state
    rm -f "$UPSTREAM_CONF.prev"
    if [[ -f $UPSTREAM_CONF ]]; then
        cp -p "$UPSTREAM_CONF" "$UPSTREAM_CONF.prev"
    fi
    write_upstream "$slot"
    crash_point renamed
    run "$NGINX" -t || die "nginx -t failed"
    run "$NGINX" -s reload || die "nginx -s reload failed"
    verify_route "$slot" || die "nginx did not route to $slot within ${VERIFY_TIMEOUT}s through $VERIFY_ADDR"
}

# undo_switch puts nginx back on the committed live slot; the candidate is stopped only once nginx
# is seen routing to the live slot again.
undo_switch() {
    log "restoring upstream.conf for ${st_live:-no slot} and reloading nginx"
    restore_upstream
    run "$NGINX" -s reload || log "nginx -s reload failed; checking where nginx routes"
    if [[ -n $st_live ]] && ! verify_route "$st_live"; then
        log "error: cannot confirm nginx routes to $st_live; $st_candidate is left running. Fix nginx, then rerun release.sh to finish undoing the switch"
        return 1
    fi
    st_phase=prepared
    save_state
    abandon
}

abandon() {
    log "stopping $st_candidate; ${st_live:-nothing} keeps serving"
    stop_slot "$st_candidate" || return 1
    st_phase=idle st_candidate=""
    save_state
}

commit() {
    st_retiring=$st_live st_live=$1 st_candidate="" st_phase=committed
    printf -v "st_committed_$1" 1
    save_state
    rm -f "$UPSTREAM_CONF.prev"
    log "nginx now sends to $1; this release is committed"
}

# cleanup runs after the commit point and can be rerun: boot persistence, then the old slot's drain
# and stop, then pruning.
cleanup() {
    local failed=0
    persist_boot "$st_live" "$st_retiring" || failed=1
    if [[ -n $st_retiring ]]; then
        sleep "$SWITCH_SETTLE"
        log "stopping $st_retiring (drain and in-flight requests, up to ${stop_secs}s)"
        stop_slot "$st_retiring" || failed=1
    fi
    if [[ $mode == systemd ]]; then
        prune_releases || failed=1
    fi
    if ((failed)); then
        log "error: deployed, cleanup failed: $st_live is live; rerun release.sh to finish the cleanup"
        return 1
    fi
    st_phase=idle st_retiring=""
    save_state
}

reconcile() {
    case $st_phase in
        idle) ;;
        prepared)
            log "an earlier run stopped before its switch"
            abandon || die "could not stop $st_candidate"
            ;;
        switching)
            log "an earlier run stopped during its switch to $st_candidate"
            undo_switch || exit 4
            ;;
        committed)
            log "an earlier run committed $st_live but did not finish its cleanup"
            cleanup || exit 3
            ;;
        *) die "unknown phase '$st_phase' in $STATE_FILE" ;;
    esac
}

on_exit() {
    local status=$?
    trap - EXIT
    if ((status != 0)); then
        case $st_phase in
            prepared) abandon || log "error: could not stop $st_candidate" ;;
            switching) undo_switch || status=4 ;;
        esac
    fi
    release_lock
    exit "$status"
}

finish() {
    cleanup || exit 3
    log "done: $st_live is live"
}

deploy() {
    local artifact=$1 next dir sum digest_re='^[^@[:space:]]+@sha256:[0-9a-f]{64}$'
    next=$(other_slot "${st_live:-green}")
    log "live: ${st_live:-none}, deploying to $next"
    if [[ $mode == docker ]]; then
        [[ $artifact =~ $digest_re ]] || die "--docker deploys by digest: pass image@sha256:<digest>, not $artifact"
        if ! run "$DOCKER" image inspect "$artifact" >/dev/null 2>&1; then
            run "$DOCKER" pull "$artifact"
        fi
        migrate_docker "$artifact"
        printf -v "st_release_$next" '%s' "$artifact"
        printf -v "st_committed_$next" 0
        begin "$next"
        run_container "$next" "$artifact"
    else
        dir=$(install_release "$artifact")
        log "installed $dir"
        migrate_systemd "$dir/$DEPLOY_NAME"
        sum=$(sha256_of "$dir/$DEPLOY_NAME")
        printf -v "st_release_$next" '%s' "$sum"
        printf -v "st_committed_$next" 0
        begin "$next"
        stop_slot "$next"
        ln -sfn "$dir" "$DEPLOY_ROOT/slots/$next"
        start_slot "$next"
    fi
    wait_ready "$next"
    switch_to "$next"
    commit "$next"
    finish
}

rollback() {
    local target committed release
    [[ -n $st_live ]] || die "nothing is live yet, so there is nothing to roll back to"
    target=$(other_slot "$st_live")
    committed=st_committed_$target release=st_release_$target
    [[ ${!committed} == 1 && -n ${!release} ]] ||
        die "slot $target holds a release that was never live (${!release:-none}); rollback only returns to a release that was live before, so deploy the one you want instead"
    slot_holds "$target" "${!release}" || die "slot $target no longer holds ${!release}; deploy the release you want instead"
    log "rolling back from $st_live to $target (${!release})"
    begin "$target"
    start_slot "$target"
    wait_ready "$target"
    switch_to "$target"
    commit "$target"
    finish
}

main() {
    if [[ ${1:-} == --docker ]]; then
        mode=docker
        shift
    fi
    [[ $# -eq 1 && -n $1 ]] || usage
    preflight
    mkdir -p "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
    take_lock
    trap on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    load_state
    reconcile
    if [[ $1 == rollback ]]; then
        rollback
    else
        deploy "$1"
    fi
}

main "$@"
