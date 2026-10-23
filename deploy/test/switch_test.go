//go:build deploytest

// Package deploytest drives deploy/release.sh against two real slots behind nginx under continuous
// requests, through the failures it must survive. Run it with make deploy-test; it needs Docker and the
// local Postgres. DEPLOYTEST_DOCKER=1 adds the --docker mode case.
//
//nolint:forbidigo,gosec // a process harness: it reads the test environment, times runs, and runs go, docker and release.sh with arguments it builds
package deploytest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

const (
	nginxImage      = "nginx:1.30.6-alpine"
	registryImage   = "registry:3.1.2"
	distrolessImage = "gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88"
	defaultAdminURL = "postgres://keel:keel-local@127.0.0.1:5442/keel?sslmode=disable"
	getWorkers      = 8
	rolePrefix      = "keel"
	loginPassword   = "deploytest"
	quickTimeout    = "READY_TIMEOUT=3"
	quickVerify     = "VERIFY_TIMEOUT=3"
)

var probePaths = []string{"/api/v1/ping", "/readyz", "/livez"}

// fakeSystemctl stands in for systemd: it runs a slot the way app@.service does, stops it with SIGTERM
// and waits for the exit like systemctl stop, and records enable and disable. fd 9 is release.sh's
// lock and must not leak into a slot.
const fakeSystemctl = `#!/usr/bin/env bash
set -euo pipefail
[[ $1 != --quiet ]] || shift
slot=${2#*@}
pidfile=$SLOT_DIR/$slot.pid
case $1 in
start)
	if [[ -f $pidfile ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then exit 0; fi
	bin=$DEPLOY_ROOT/slots/$slot/app
	"$bin" migrate:validate >/dev/null
	(
		set -a
		. "$ENV_DIR/app.env"
		. "$ENV_DIR/$slot.env"
		set +a
		export APP_DATABASE_URL_FILE=$CRED_DIR/database_url APP_DATABASE_OPERATOR_URL_FILE=$CRED_DIR/database_operator_url
		exec "$bin" serve
	) </dev/null >>"$SLOT_DIR/$slot.log" 2>&1 9>&- &
	echo $! >"$pidfile"
	;;
stop)
	[[ -f $pidfile ]] || exit 0
	pid=$(cat "$pidfile")
	if kill -TERM "$pid" 2>/dev/null; then
		for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
		kill -KILL "$pid" 2>/dev/null || true
	fi
	rm -f "$pidfile"
	;;
enable) touch "$SLOT_DIR/$slot.enabled" ;;
disable) rm -f "$SLOT_DIR/$slot.enabled" ;;
esac
`

// fakeSystemdRun runs the command the way a transient unit would: only app.env and the loaded
// credentials, and it refuses to run without a User= so a migration can never run as root.
const fakeSystemdRun = `#!/usr/bin/env bash
set -euo pipefail
user="" envfile=/dev/null
creds=$(mktemp -d)
trap 'rm -rf "$creds"' EXIT
while [[ $# -gt 0 ]]; do
	case $1 in
	-p)
		case $2 in
		User=*) user=${2#User=} ;;
		EnvironmentFile=*) envfile=${2#EnvironmentFile=} ;;
		LoadCredential=*) c=${2#LoadCredential=}; cp "${c#*:}" "$creds/${c%%:*}" ;;
		esac
		shift 2
		;;
	--*) shift ;;
	*) break ;;
	esac
done
[[ -n $user ]] || { echo "systemd-run: no User=; the command would run as root" >&2; exit 1; }
env -i PATH="$PATH" CREDENTIALS_DIRECTORY="$creds" bash -c 'set -a; . "$1"; set +a; shift; "$@"' sh "$envfile" "$@" 9>&-
`

// nginxStub fails or skips one nginx command and passes every other to REAL_NGINX.
const nginxStub = `#!/usr/bin/env bash
set -euo pipefail
mode=$1
shift
read -r -a real <<<"$REAL_NGINX"
case "$mode $*" in
"fail-test -t") echo "nginx: [emerg] stub: configuration test failed" >&2; exit 1 ;;
"fail-reload -s reload") echo "nginx: [error] stub: reload failed" >&2; exit 1 ;;
"noop-reload -s reload") exit 0 ;;
esac
exec "${real[@]}" "$@"
`

// failingMigration is a release whose migration fails after the validation passed.
const failingMigration = `#!/bin/sh
case $1 in migrate) echo "ERROR: stub migration failed" >&2; exit 1 ;; esac
exec %q "$@"
`

type harness struct {
	root      string
	work      string
	env       []string
	conf      string
	state     string
	slotDir   string
	ports     map[string]int
	releases  atomic.Int64
	docker    bool
	appName   string
	nginx     string
	base      string
	bin       string
	stageRoot string
	urls      map[string]string
}

func TestSystemdSwitch(t *testing.T) {
	ctx := t.Context()
	h := newHarness(ctx, t, false)
	h.release(ctx, t, nil, h.bin)
	h.expectLive(ctx, t, h.live(t))

	notReady := h.buildNotReady(ctx, t)
	failMigrate := filepath.Join(h.work, "fail-migrate")
	writeFile(t, failMigrate, fmt.Sprintf(failingMigration, h.bin), 0o755)
	badSum := filepath.Join(h.work, "bad-sum", "app")
	copyFile(t, h.bin, badSum)
	writeFile(t, badSum+".sha256", strings.Repeat("0", 64)+"  app\n", 0o644)

	l := startLoad(ctx, h.base)
	step := func(name string, fn func(t *testing.T, live, other string)) {
		t.Run(name, func(t *testing.T) {
			seen := l.failureCount()
			live := h.live(t)
			fn(t, live, otherSlot(live))
			time.Sleep(500 * time.Millisecond)
			l.expectNoFailuresSince(t, seen)
		})
	}

	step("release, rollback and boot persistence", func(t *testing.T, live, other string) {
		h.release(ctx, t, nil, h.bin)
		h.expectLive(ctx, t, other)
		h.expectBoot(ctx, t, other)
		h.expectStopped(ctx, t, live)
		h.release(ctx, t, nil, "rollback")
		h.expectLive(ctx, t, live)
		h.expectBoot(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("preflight refuses an unsafe configuration", func(t *testing.T, live, other string) {
		for _, c := range []struct{ appEnv, blue, want string }{
			{"APP_HTTP_WRITE_TIMEOUT=60s", "127.0.0.1:8081", "must be at least"},
			{"APP_HTTP_SHUTDOWN_DRAIN=5", "127.0.0.1:8081", "cannot read duration"},
			{"APP_HTTP_SHUTDOWN_TIMEOUT=1m5", "127.0.0.1:8081", "cannot read duration"},
			{"APP_HTTP_WRITE_TIMEOUT=5s", "0.0.0.0:8081", "127.0.0.0/8"},
			{"APP_HTTP_WRITE_TIMEOUT=5s", "app.example.com:8081", "127.0.0.0/8"},
		} {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "app.env"), c.appEnv+"\n", 0o600)
			writeFile(t, filepath.Join(dir, "blue.env"), "APP_HTTP_ADDR="+c.blue+"\n", 0o600)
			writeFile(t, filepath.Join(dir, "green.env"), "APP_HTTP_ADDR=127.0.0.1:8082\n", 0o600)
			h.fail(ctx, t, []string{"ENV_DIR=" + dir}, h.bin, c.want)
		}
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("a release that listens but never becomes ready is stopped", func(t *testing.T, live, other string) {
		h.fail(ctx, t, []string{quickTimeout}, notReady, "not ready")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("rollback refuses a release that was never live", func(t *testing.T, live, other string) {
		h.fail(ctx, t, nil, "rollback", "never live")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("nginx -t fails", func(t *testing.T, live, other string) {
		h.fail(ctx, t, h.stub("fail-test"), h.bin, "nginx -t failed")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("nginx reload fails", func(t *testing.T, live, other string) {
		h.fail(ctx, t, h.stub("fail-reload"), h.bin, "reload failed")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("nginx reload exits 0 without applying", func(t *testing.T, live, other string) {
		h.fail(ctx, t, append(h.stub("noop-reload"), quickVerify), h.bin, "did not route")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("a crash right after the rename is reconciled by the next run", func(t *testing.T, live, other string) {
		h.fail(ctx, t, []string{"RELEASE_TEST_CRASH_AT=renamed"}, h.bin, "")
		if b, _ := os.ReadFile(filepath.Join(h.state, "state")); !strings.Contains(string(b), "phase=switching\n") {
			t.Fatalf("the crash should leave the switch phase for the next run:\n%s", b)
		}
		h.release(ctx, t, nil, h.bin)
		h.expectLive(ctx, t, other)
		h.expectStopped(ctx, t, live)
	})

	step("two releases at once", func(t *testing.T, live, other string) {
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Go(func() { errs[i] = h.run(ctx, t, nil, h.bin) })
		}
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("exactly one of two concurrent releases should succeed, got %v and %v", errs[0], errs[1])
		}
		h.expectLive(ctx, t, other)
		h.expectStopped(ctx, t, live)
	})

	step("a failed migration leaves the live slot alone", func(t *testing.T, live, other string) {
		h.fail(ctx, t, nil, failMigrate, "Recovering a failed migration")
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("a checksum mismatch installs nothing", func(t *testing.T, live, other string) {
		before := h.releaseDirs(t)
		h.fail(ctx, t, nil, badSum, "does not match")
		if after := h.releaseDirs(t); after != before {
			t.Fatalf("a release directory was created for a binary that failed its checksum (%d, now %d)", before, after)
		}
		h.expectLive(ctx, t, live)
		h.expectStopped(ctx, t, other)
	})

	step("a request in flight when its slot retires is answered", func(t *testing.T, live, other string) {
		answer := make(chan string, 1)
		go func() { answer <- h.hold(ctx) }()
		time.Sleep(300 * time.Millisecond)
		h.release(ctx, t, nil, h.bin)
		if got := <-answer; !strings.Contains(got, `"retired":true`) {
			t.Fatalf("the held request should be answered after its slot was told to stop, got %s", got)
		}
		h.expectLive(ctx, t, other)
		h.expectStopped(ctx, t, live)
	})

	step("the production profile starts", func(t *testing.T, live, other string) {
		envDir := h.productionLayout(ctx, t)
		h.release(ctx, t, []string{"ENV_DIR=" + envDir, "CRED_DIR=" + filepath.Join(envDir, "credentials")}, h.bin)
		h.expectLive(ctx, t, other)
		h.expectStopped(ctx, t, live)
		h.release(ctx, t, nil, h.bin)
		h.expectLive(ctx, t, live)
	})

	l.finish(t)
}

// hold asks the live slot, through nginx, for the hold route and returns its answer.
func (h *harness) hold(ctx context.Context) string {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/api/v1/deploytest/hold", nil)
	resp, err := client.Do(req)
	if err != nil {
		return err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.Status + " " + string(b)
}

// productionLayout writes app.env and credentials for the production profile: https public URL, mail
// over SMTP as the notifier, signing keys, and database URLs that verify TLS. The database is reached
// through a TLS proxy with a throwaway CA, since the local Postgres serves no TLS.
func (h *harness) productionLayout(ctx context.Context, t *testing.T) string {
	t.Helper()
	dir := filepath.Join(h.work, "etc-production")
	proxy, caFile := startTLSProxy(ctx, t, h.urls["database_url"], dir)
	writeFile(t, filepath.Join(dir, "app.env"), strings.Join([]string{
		"APP_ENV=production",
		"APP_PUBLIC_URL=https://app.example.test",
		"APP_LOG_FORMAT=json",
		"APP_PROXY_TRUSTED=127.0.0.1/32",
		"APP_HTTP_WRITE_TIMEOUT=10s",
		"APP_HTTP_SHUTDOWN_DRAIN=1s",
		"APP_HTTP_SHUTDOWN_TIMEOUT=10s",
		"APP_JOBS_SHUTDOWN_GRACE=5s",
		"APP_RATE_PREAUTH=1000000/1m",
		"APP_RATE_AUTH=1000000/1m",
		"APP_RATE_API_READ=1000000/1m",
		"APP_RATE_HEALTH=1000000/1m",
		"APP_SESSION_KEYS=ZGVwbG95dGVzdC1wcm9kdWN0aW9uLXNpZ25pbmcta2V5IQ==",
		"APP_MAIL_DRIVER=smtp",
		"APP_MAIL_FROM=no-reply@example.test",
		"APP_MAIL_SMTP_HOST=127.0.0.1",
		"APP_MAIL_SMTP_TLS=none",
		"APP_DATABASE_CA_FILE=" + caFile,
	}, "\n")+"\n", 0o600)
	for slot, port := range h.ports {
		writeFile(t, filepath.Join(dir, slot+".env"), fmt.Sprintf("APP_HTTP_ADDR=127.0.0.1:%d\n", port), 0o600)
	}
	for name, raw := range h.urls {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		u.Host = proxy
		q := u.Query()
		q.Set("sslmode", "verify-full")
		q.Set("sslnegotiation", "direct")
		u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
		writeFile(t, filepath.Join(dir, "credentials", name), u.String(), 0o600)
	}
	return dir
}

// startTLSProxy terminates direct TLS (Postgres 17's sslnegotiation=direct, ALPN postgresql) with a
// certificate for 127.0.0.1 and forwards the plain protocol to the database in rawURL. It returns its
// address and the CA file that verifies it.
func startTLSProxy(ctx context.Context, t *testing.T, rawURL, dir string) (string, string) {
	t.Helper()
	target, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "database-ca.pem")
	writeFile(t, caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	var lc net.ListenConfig
	plain, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(plain, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"postgresql"}, MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go forward(ctx, client, target.Host)
		}
	}()
	return plain.Addr().String(), caFile
}

func forward(ctx context.Context, client net.Conn, target string) {
	defer func() { _ = client.Close() }()
	var d net.Dialer
	server, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(server, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, server); done <- struct{}{} }()
	<-done
}

func TestDockerSwitch(t *testing.T) {
	if os.Getenv("DEPLOYTEST_DOCKER") != "1" {
		t.Skip("set DEPLOYTEST_DOCKER=1 to run the --docker mode case")
	}
	ctx := t.Context()
	h := newHarness(ctx, t, true)
	first, second := h.pushImages(ctx, t)
	h.release(ctx, t, nil, first)
	live := h.live(t)
	h.expectLive(ctx, t, live)
	h.expectStaged(t, live)

	l := startLoad(ctx, h.base)
	h.fail(ctx, t, nil, strings.SplitN(second, "@", 2)[0]+":v2", "by digest")
	h.release(ctx, t, nil, second)
	h.expectLive(ctx, t, otherSlot(live))
	h.expectBoot(ctx, t, otherSlot(live))
	h.expectStopped(ctx, t, live)
	h.expectStaged(t, otherSlot(live))

	h.release(ctx, t, nil, "rollback")
	h.expectLive(ctx, t, live)
	h.expectBoot(ctx, t, live)
	h.expectStopped(ctx, t, otherSlot(live))
	h.expectStaged(t, live)
	if img := h.containerImage(ctx, t, live); img != first {
		t.Fatalf("rollback should run %s again, %s-%s runs %s", first, h.appName, live, img)
	}
	l.finish(t)
}

func newHarness(ctx context.Context, t *testing.T, docker bool) *harness {
	t.Helper()
	h := &harness{root: repoRoot(t), work: t.TempDir(), docker: docker, appName: "app"}
	if docker {
		h.appName = fmt.Sprintf("keel-deploytest-%d", time.Now().UnixNano())
	}
	h.bin = h.buildApp(ctx, t, runtime.GOOS, filepath.Join(h.work, "app"))
	urls := createDatabase(ctx, t)
	if docker {
		for name, u := range urls {
			urls[name] = containerReachable(t, u)
		}
	}
	h.ports = map[string]int{"blue": freePort(ctx, t), "green": freePort(ctx, t)}
	h.urls = urls
	h.layout(ctx, t, urls)
	nginxPort, verifyPort := freePort(ctx, t), freePort(ctx, t)
	h.startNginx(ctx, t, nginxPort, verifyPort)
	h.base = fmt.Sprintf("http://127.0.0.1:%d", nginxPort)
	return h
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func (h *harness) buildApp(ctx context.Context, t *testing.T, goos, out string) string {
	t.Helper()
	// The deploytest tag adds the hold route, which answers only after its slot was told to stop.
	h.goBuild(ctx, t, []string{"CGO_ENABLED=0", "GOOS=" + goos}, out, "-tags", "deploytest", "./cmd/app")
	return out
}

func (h *harness) buildNotReady(ctx context.Context, t *testing.T) string {
	t.Helper()
	out := filepath.Join(h.work, "notready", "app")
	h.goBuild(ctx, t, []string{"CGO_ENABLED=0"}, out, "-tags", "deploytest", "./deploy/test/notready")
	return out
}

func (h *harness) goBuild(ctx context.Context, t *testing.T, env []string, out string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "go", append([]string{"build", "-trimpath", "-o", out}, args...)...)
	cmd.Dir = h.root
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %v: %v\n%s", args, err, b)
	}
}

// createDatabase makes a throwaway database the way testdb does. The app and operator log in directly as
// throwaway members of the shared roles (the app refuses a role switched through startup options); the
// owner is reached through SET ROLE, which only migrations use. It returns each role's URL by credential
// name.
func createDatabase(ctx context.Context, t *testing.T) map[string]string {
	t.Helper()
	adminURL := os.Getenv("APP_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = defaultAdminURL
	}
	admin := openPostgres(ctx, t, adminURL)
	owner, app, operator := rolePrefix+"_owner", rolePrefix+"_app", rolePrefix+"_operator"
	for _, role := range []string{owner, app, operator} {
		attrs := "NOBYPASSRLS"
		if role == operator {
			attrs = "BYPASSRLS"
		}
		mustExec(ctx, t, admin, fmt.Sprintf(`DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN CREATE ROLE %[1]s NOLOGIN %[2]s; END IF;
		END $$`, role, attrs))
	}
	name := fmt.Sprintf("%s_deploytest_%d", rolePrefix, time.Now().UnixNano())
	logins := map[string]string{app: name + "_app", operator: name + "_operator"}
	mustExec(ctx, t, admin, fmt.Sprintf("CREATE DATABASE %s OWNER %s", name, owner))
	t.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		mustExec(ctx, t, admin, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name))
		for _, login := range logins {
			mustExec(ctx, t, admin, "DROP ROLE IF EXISTS "+login)
		}
		_ = admin.Close()
	})
	for role, login := range logins {
		bypass := "NOBYPASSRLS"
		if role == operator {
			bypass = "BYPASSRLS" // an attribute, not inherited through membership
		}
		mustExec(ctx, t, admin, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' %s IN ROLE %s", login, loginPassword, bypass, role))
	}

	scoped := openPostgres(ctx, t, roleURL(t, adminURL, name, "", ""))
	defer func() { _ = scoped.Close() }()
	for _, stmt := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s, %s", app, operator),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s, %s", owner, app, operator),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s, %s", owner, app, operator),
	} {
		mustExec(ctx, t, scoped, stmt)
	}
	return map[string]string{
		"database_url":          roleURL(t, adminURL, name, "", logins[app]),
		"database_operator_url": roleURL(t, adminURL, name, "", logins[operator]),
		"database_migrate_url":  roleURL(t, adminURL, name, owner, ""),
	}
}

// containerReachable points a loopback database URL at the host as a container on the default bridge
// sees it.
func containerReachable(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host := "host.docker.internal"
	if runtime.GOOS == "linux" {
		host = "172.17.0.1"
	}
	u.Host = net.JoinHostPort(host, u.Port())
	return u.String()
}

func openPostgres(ctx context.Context, t *testing.T, rawURL string) *sql.DB {
	t.Helper()
	cfg := db.Defaults()
	cfg.MaxOpen, cfg.MaxIdle = 2, 1
	pool, _, err := db.OpenSQL(ctx, rawURL, cfg)
	if err != nil {
		t.Fatalf("connect to Postgres (set APP_TEST_DATABASE_URL to an admin URL): %v", err)
	}
	return pool
}

func mustExec(ctx context.Context, t *testing.T, pool *sql.DB, stmt string) {
	t.Helper()
	if _, err := pool.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

func roleURL(t *testing.T, adminURL, database, role, login string) string {
	t.Helper()
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	if login != "" {
		u.User = url.UserPassword(login, loginPassword)
	}
	u.Path = "/" + database
	q := u.Query()
	if role != "" {
		q.Set("options", "-c role="+role)
	}
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return u.String()
}

func freePort(ctx context.Context, t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, string(b), 0o755)
}

func otherSlot(slot string) string {
	if slot == "blue" {
		return "green"
	}
	return "blue"
}

// layout builds the host the way docs/operations.md describes, under a temporary root.
func (h *harness) layout(ctx context.Context, t *testing.T, credentials map[string]string) {
	t.Helper()
	appRoot := filepath.Join(h.work, "srv")
	envDir := filepath.Join(h.work, "etc")
	credDir := filepath.Join(envDir, "credentials")
	h.slotDir = filepath.Join(h.work, "slots")
	h.state = filepath.Join(h.work, "var", "deploy")
	h.stageRoot = filepath.Join(h.work, "var", "stage")
	h.conf = filepath.Join(h.work, "nginx", "upstream.conf")
	for _, dir := range []string{appRoot, h.slotDir, filepath.Dir(h.conf)} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(envDir, "app.env"), strings.Join([]string{
		"APP_ENV=local",
		"APP_LOG_FORMAT=json",
		"APP_PROXY_TRUSTED=127.0.0.1/32",
		"APP_HTTP_WRITE_TIMEOUT=10s",
		"APP_HTTP_SHUTDOWN_DRAIN=1s",
		"APP_HTTP_SHUTDOWN_TIMEOUT=10s",
		"APP_JOBS_SHUTDOWN_GRACE=5s",
		"APP_RATE_PREAUTH=1000000/1m",
		"APP_RATE_AUTH=1000000/1m",
		"APP_RATE_API_READ=1000000/1m",
		"APP_RATE_HEALTH=1000000/1m",
	}, "\n")+"\n", 0o600)
	for slot, port := range h.ports {
		writeFile(t, filepath.Join(envDir, slot+".env"), fmt.Sprintf("APP_HTTP_ADDR=127.0.0.1:%d\n", port), 0o600)
	}
	for name, value := range credentials {
		writeFile(t, filepath.Join(credDir, name), value, 0o600)
	}
	// The first release finds the shipped upstream.conf, naming blue, already in place.
	writeFile(t, h.conf, fmt.Sprintf("# slot: blue\nupstream %s {\n    server 127.0.0.1:%d;\n}\n", h.appName, h.ports["blue"]), 0o644)
	systemctl := filepath.Join(h.work, "bin", "systemctl")
	writeFile(t, systemctl, fakeSystemctl, 0o755)
	systemdRun := filepath.Join(h.work, "bin", "systemd-run")
	writeFile(t, systemdRun, fakeSystemdRun, 0o755)
	writeFile(t, filepath.Join(h.work, "bin", "nginx-stub"), nginxStub, 0o755)

	h.env = []string{
		"DEPLOY_NAME=" + h.appName,
		"DEPLOY_ROOT=" + appRoot,
		"ENV_DIR=" + envDir,
		"CRED_DIR=" + credDir,
		"STATE_DIR=" + h.state,
		"STAGE_DIR=" + h.stageRoot,
		"SLOT_DIR=" + h.slotDir,
		"UPSTREAM_CONF=" + h.conf,
		"LOCK_FILE=" + filepath.Join(h.work, "release.lock"),
		"SYSTEMCTL=" + systemctl,
		"SYSTEMD_RUN=" + systemdRun,
		fmt.Sprintf("CONTAINER_USER=%d:%d", os.Getuid(), os.Getgid()),
		"SWITCH_SETTLE=1",
		"READY_TIMEOUT=30",
	}
	if runtime.GOOS != "linux" {
		h.env = append(h.env, "UPSTREAM_HOST=host.docker.internal")
	}
	t.Cleanup(func() { h.cleanupSlots(context.WithoutCancel(ctx), t) })
}

func (h *harness) cleanupSlots(ctx context.Context, t *testing.T) {
	if t.Failed() {
		for slot := range h.ports {
			if b, err := os.ReadFile(filepath.Join(h.slotDir, slot+".log")); err == nil {
				t.Logf("%s log (last 2 KiB):\n%s", slot, b[max(0, len(b)-2048):])
			}
		}
	}
	for slot := range h.ports {
		var cmd *exec.Cmd
		if h.docker {
			cmd = exec.CommandContext(ctx, "docker", "rm", "-f", h.appName+"-"+slot)
		} else {
			cmd = exec.CommandContext(ctx, filepath.Join(h.work, "bin", "systemctl"), "stop", "app@"+slot)
		}
		cmd.Env = append(os.Environ(), h.env...)
		_ = cmd.Run()
	}
	// Staged credentials are read-only directories; make them removable for t.TempDir's cleanup.
	_ = filepath.WalkDir(h.stageRoot, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func (h *harness) stub(mode string) []string {
	return []string{"NGINX=" + filepath.Join(h.work, "bin", "nginx-stub") + " " + mode, "REAL_NGINX=" + h.nginx}
}

func (h *harness) run(ctx context.Context, t *testing.T, extra []string, args ...string) error {
	t.Helper()
	_, err := h.runLog(ctx, t, extra, args...)
	return err
}

func (h *harness) runLog(ctx context.Context, t *testing.T, extra []string, args ...string) (string, error) {
	t.Helper()
	n := h.releases.Add(1)
	logPath := filepath.Join(h.work, fmt.Sprintf("release-%d.log", n))
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	if h.docker {
		args = append([]string{"--docker"}, args...)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(h.root, "deploy", "release.sh"), args...)
	cmd.Env = append(append(os.Environ(), h.env...), "NGINX="+h.nginx)
	cmd.Env = append(cmd.Env, extra...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	start := time.Now()
	err = cmd.Run()
	out, _ := os.ReadFile(logPath)
	t.Logf("release.sh %s (%s, %v):\n%s", strings.Join(args, " "), time.Since(start).Round(100*time.Millisecond), err, out)
	return string(out), err
}

func (h *harness) release(ctx context.Context, t *testing.T, extra []string, args ...string) {
	t.Helper()
	if err := h.run(ctx, t, extra, args...); err != nil {
		t.Fatalf("release.sh %s: %v", strings.Join(args, " "), err)
	}
}

// fail expects release.sh to fail with want in its output.
func (h *harness) fail(ctx context.Context, t *testing.T, extra []string, arg, want string) {
	t.Helper()
	out, err := h.runLog(ctx, t, extra, arg)
	if err == nil {
		t.Fatalf("release.sh %s should have failed", arg)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("release.sh %s should say %q", arg, want)
	}
}

// live is the committed live slot from release.sh's state file.
func (h *harness) live(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "state"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "live="); ok {
			return v
		}
	}
	t.Fatalf("no live slot in the state file:\n%s", b)
	return ""
}

// expectLive checks the state file, upstream.conf and the running process agree on slot.
func (h *harness) expectLive(ctx context.Context, t *testing.T, slot string) {
	t.Helper()
	if got := h.live(t); got != slot {
		t.Fatalf("live slot is %s, want %s", got, slot)
	}
	b, err := os.ReadFile(h.conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "# slot: "+slot+"\n") || !strings.Contains(string(b), fmt.Sprintf(":%d;", h.ports[slot])) {
		t.Fatalf("upstream.conf should name %s:\n%s", slot, b)
	}
	if !h.running(ctx, t, slot) {
		t.Fatalf("live slot %s is not running", slot)
	}
}

func (h *harness) expectBoot(ctx context.Context, t *testing.T, slot string) {
	t.Helper()
	if !h.persistent(ctx, t, slot) || h.persistent(ctx, t, otherSlot(slot)) {
		t.Fatalf("only the live slot %s should start at boot", slot)
	}
}

func (h *harness) expectStopped(ctx context.Context, t *testing.T, slot string) {
	t.Helper()
	if h.running(ctx, t, slot) {
		t.Fatalf("slot %s still runs after release.sh finished", slot)
	}
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", h.ports[slot]))
	if err == nil {
		_ = conn.Close()
		t.Fatalf("slot %s still listens after release.sh finished", slot)
	}
	if h.docker {
		if _, err := os.Stat(filepath.Join(h.stageRoot, slot)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stopped slot %s still has staged credentials (%v)", slot, err)
		}
	}
}

func (h *harness) running(ctx context.Context, t *testing.T, slot string) bool {
	t.Helper()
	if h.docker {
		return h.inspect(ctx, t, slot, "{{.State.Running}}") == "true"
	}
	b, err := os.ReadFile(filepath.Join(h.slotDir, slot+".pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.FindProcess(pid)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

func (h *harness) persistent(ctx context.Context, t *testing.T, slot string) bool {
	t.Helper()
	if h.docker {
		return h.inspect(ctx, t, slot, "{{.HostConfig.RestartPolicy.Name}}") == "unless-stopped"
	}
	_, err := os.Stat(filepath.Join(h.slotDir, slot+".enabled"))
	return err == nil
}

func (h *harness) inspect(ctx context.Context, t *testing.T, slot, format string) string {
	t.Helper()
	b, err := exec.CommandContext(ctx, "docker", "container", "inspect", "-f", format, h.appName+"-"+slot).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (h *harness) containerImage(ctx context.Context, t *testing.T, slot string) string {
	t.Helper()
	return h.inspect(ctx, t, slot, "{{.Config.Image}}")
}

// expectStaged checks the live container's credentials: a 0500 directory of 0400 files without the
// migration credential.
func (h *harness) expectStaged(t *testing.T, slot string) {
	t.Helper()
	dir := filepath.Join(h.stageRoot, slot)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("no staged credentials for %s: %v", slot, err)
	}
	if info.Mode().Perm() != 0o500 {
		t.Fatalf("staged directory mode is %v, want 0500", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "database_migrate_url" || fi.Mode().Perm() != 0o400 {
			t.Fatalf("staged %s with mode %v; want 0400 and no migration credential", e.Name(), fi.Mode().Perm())
		}
	}
}

func (h *harness) releaseDirs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.work, "srv", "releases"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// pushImages builds two images of the app on the shipped distroless base and pushes them to a
// throwaway registry, so they can be deployed by digest.
func (h *harness) pushImages(ctx context.Context, t *testing.T) (first, second string) {
	t.Helper()
	port := freePort(ctx, t)
	registry := fmt.Sprintf("keel-deploytest-registry-%d", time.Now().UnixNano())
	dockerRun(ctx, t, registry, "run", "-d", "--name", registry, "-p", fmt.Sprintf("127.0.0.1:%d:5000", port), registryImage)
	t.Cleanup(func() { removeContainer(context.WithoutCancel(ctx), registry) })

	dir := filepath.Join(h.work, "image")
	h.buildApp(ctx, t, "linux", filepath.Join(dir, "app"))
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+distrolessImage+"\nARG N\nLABEL n=$N\nCOPY app /app\nUSER nonroot:nonroot\nENTRYPOINT [\"/app\"]\n", 0o644)
	repo := fmt.Sprintf("127.0.0.1:%d/%s", port, h.appName)
	refs := make([]string, 2)
	for i := range refs {
		tag := fmt.Sprintf("%s:v%d", repo, i+1)
		dockerCmd(ctx, t, "build", "-q", "--build-arg", fmt.Sprintf("N=%d", i), "-t", tag, dir)
		pushWithRetry(ctx, t, tag)
		digest := dockerCmd(ctx, t, "image", "inspect", "-f", "{{range .RepoDigests}}{{println .}}{{end}}", tag)
		refs[i] = strings.Fields(digest)[0]
		t.Cleanup(func() {
			_ = exec.CommandContext(context.WithoutCancel(ctx), "docker", "rmi", "-f", tag).Run()
		})
	}
	return refs[0], refs[1]
}

func dockerCmd(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	b, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, b)
	}
	return strings.TrimSpace(string(b))
}

// dockerRun starts a container, retrying a port Docker Desktop has not yet released from an earlier
// container; the name is removed before each retry.
func dockerRun(ctx context.Context, t *testing.T, name string, args ...string) {
	t.Helper()
	var out []byte
	var err error
	for range 5 {
		if out, err = exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err == nil {
			return
		}
		if !strings.Contains(string(out), "address already in use") {
			break
		}
		removeContainer(ctx, name)
		time.Sleep(time.Second)
	}
	t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
}

// pushWithRetry waits out the registry's start.
func pushWithRetry(ctx context.Context, t *testing.T, tag string) {
	t.Helper()
	var out []byte
	var err error
	for range 20 {
		if out, err = exec.CommandContext(ctx, "docker", "push", "-q", tag).CombinedOutput(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("docker push %s: %v\n%s", tag, err, out)
}

func removeContainer(ctx context.Context, name string) {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
}

// startNginx runs the shipped site file, reduced to plain HTTP, in a container.
func (h *harness) startNginx(ctx context.Context, t *testing.T, port, verifyPort int) {
	t.Helper()
	shipped, err := os.ReadFile(filepath.Join(h.root, "deploy", "nginx", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("keel-deploytest-nginx-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--name", name}
	listen, verify := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.1:%d", verifyPort)
	if runtime.GOOS == "linux" {
		args = append(args, "--network", "host")
	} else {
		listen, verify = "8080", "8079"
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:8080", port), "-p", fmt.Sprintf("127.0.0.1:%d:8079", verifyPort))
	}
	site := filepath.Join(h.work, "site.conf")
	conf := strings.ReplaceAll(plainHTTP(string(shipped), listen, verify), "http://app;", "http://"+h.appName+";")
	writeFile(t, site, conf, 0o644)
	args = append(args,
		"-v", site+":/etc/nginx/conf.d/default.conf:ro",
		"-v", filepath.Dir(h.conf)+":/etc/nginx/app:ro",
		nginxImage)
	t.Cleanup(func() { removeContainer(context.WithoutCancel(ctx), name) })
	dockerRun(ctx, t, name, args...)
	h.nginx = "docker exec " + name + " nginx"
	h.env = append(h.env, "VERIFY_ADDR=127.0.0.1:"+strconv.Itoa(verifyPort))
}

// plainHTTP drops the redirect server and the TLS lines from the shipped site, listens on listen, and
// moves the loopback verification server to verify.
func plainHTTP(conf, listen, verify string) string {
	var out, block []string
	depth := 0
	for line := range strings.SplitSeq(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if depth == 0 && !strings.HasPrefix(trimmed, "server ") {
			out = append(out, line)
			continue
		}
		if depth == 1 && (strings.HasPrefix(trimmed, "listen ") || strings.HasPrefix(trimmed, "ssl_") || trimmed == "http2 on;") {
			continue
		}
		block = append(block, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth != 0 {
			continue
		}
		server := strings.Join(block, "\n")
		block = nil
		switch {
		case strings.Contains(server, "return 30"):
		case strings.Contains(server, "X-Upstream"):
			out = append(out, strings.Replace(server, "{", "{\n    listen "+verify+";", 1))
		default:
			out = append(out, strings.Replace(server, "{", "{\n    listen "+listen+";", 1))
		}
	}
	return strings.Join(out, "\n")
}

type load struct {
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	ok       atomic.Int64
	mu       sync.Mutex
	failures []string
}

// startLoad sends GETs from several workers, half reusing connections to nginx and half opening one per
// request, and a POST (a sign-in with an empty body, which answers 4xx) that nginx must never retry.
// The POST opens a connection each time: any nginx reload closes idle client connections, and Go
// retries a request that meets one only when it is idempotent.
func startLoad(ctx context.Context, base string) *load {
	ctx, cancel := context.WithCancel(ctx)
	l := &load{cancel: cancel}
	for w := range getWorkers + 1 {
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: w%2 == 1 || w == getWorkers, MaxIdleConnsPerHost: 1},
		}
		l.wg.Go(func() {
			for i := 0; ctx.Err() == nil; i++ {
				if w == getWorkers {
					l.send(ctx, client, http.MethodPost, base+"/api/v1/auth/sign-in")
					continue
				}
				l.send(ctx, client, http.MethodGet, base+probePaths[(w+i)%len(probePaths)])
			}
		})
	}
	return l
}

func (l *load) send(ctx context.Context, client *http.Client, method, target string) {
	var body io.Reader = http.NoBody
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, _ := http.NewRequestWithContext(ctx, method, target, body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if ctx.Err() != nil {
		if err == nil {
			_ = resp.Body.Close()
		}
		return
	}
	var failure string
	switch {
	case err != nil:
		failure = fmt.Sprintf("%s %s %s: %v", time.Now().Format("15:04:05.000"), method, target, err)
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if (method == http.MethodGet && resp.StatusCode/100 != 2) || resp.StatusCode >= 500 {
			failure = fmt.Sprintf("%s %s %s: %s", time.Now().Format("15:04:05.000"), method, target, resp.Status)
		}
	}
	if failure == "" {
		l.ok.Add(1)
		return
	}
	l.mu.Lock()
	l.failures = append(l.failures, failure)
	l.mu.Unlock()
}

func (l *load) failureCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.failures)
}

func (l *load) expectNoFailuresSince(t *testing.T, seen int) {
	t.Helper()
	l.mu.Lock()
	failed := l.failures[seen:]
	l.mu.Unlock()
	if len(failed) > 0 {
		t.Errorf("%d failed requests, first: %s", len(failed), strings.Join(failed[:min(len(failed), 10)], "\n"))
	}
}

func (l *load) finish(t *testing.T) {
	t.Helper()
	time.Sleep(time.Second)
	l.cancel()
	l.wg.Wait()
	t.Logf("%d requests through nginx", l.ok.Load())
	l.expectNoFailuresSince(t, 0)
	if l.ok.Load() < 100 {
		t.Fatalf("only %d requests were sent; the load did not run", l.ok.Load())
	}
}
