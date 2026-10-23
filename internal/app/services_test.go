package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

// runMaintenance runs a maintenance schedule now on q and waits until done says it has worked.
func runMaintenance(t *testing.T, q *jobs.Queue, schedule string, done func() bool) {
	t.Helper()
	_, err := q.RunSchedule(t.Context(), schedule)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- q.Run(ctx) }()
	require.Eventually(t, done, 10*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-stopped)
}

// Without tenancy maintenance runs on the plain app pool.
func TestMaintenance_RunsOnThePlainPoolWithoutTenancy(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys, "APP_JOBS_POLL=50ms", "APP_JOBS_SHUTDOWN_GRACE=0s"})
		require.NoError(t, err)
		built, err := app.Build(t.Context(), cfg, app.Deps{DB: d, Notifier: &links{}})
		require.NoError(t, err)
		past := clock.Wall(t.Context()).Now().UTC().Add(-24 * time.Hour)
		_, err = d.SQL().ExecContext(t.Context(), db.Rebind(d.Dialect(), "INSERT INTO idempotency_keys "+
			"(id, realm, principal, idem_key, request_hash, status, created_at, lease_until, expires_at) VALUES (?, 'tenant', 'maintenance-test', 'k', ?, 'done', ?, ?, ?)"),
			ids.New().String(), []byte{0}, past, past, past)
		require.NoError(t, err)
		left := func() bool {
			var n int
			require.NoError(t, d.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM idempotency_keys").Scan(&n))
			return n == 0
		}

		runMaintenance(t, built.Queue, "idempotency.prune", left)
	})
}

type probeModule struct {
	queue      *jobs.Queue
	registered bool
}

func (*probeModule) Permissions(string) []rbac.Perm { return nil }

func (m *probeModule) Register(realm string, _ huma.API) {
	m.registered = m.registered || realm == app.RealmTenant
}

func (*probeModule) Mapper(error) (*problem.Problem, bool) { return nil, false }

func (m *probeModule) Jobs(q *jobs.Queue) {
	m.queue = q
	q.Handle("probe.ping", func(context.Context, jobs.Job) error { return nil })
}

func (*probeModule) Commands(app.Opener) []cli.Command { return nil }

// Build mounts one instance of each module: the one serving its operations is the one whose jobs are on
// the queue serve runs, so a service enqueues on the queue its handlers run from.
func TestBuild_JobsMountOnTheModuleInstancesItServes(t *testing.T) {
	var made []*probeModule
	t.Cleanup(app.MountTestModules(func() []app.Module {
		m := &probeModule{}
		made = append(made, m)
		return []app.Module{m}
	}))
	cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys})
	require.NoError(t, err)

	built, err := app.Build(t.Context(), cfg, app.Deps{DB: testdb.Get(t), Notifier: &links{}})
	require.NoError(t, err)

	require.Len(t, made, 1)
	require.NotEmpty(t, built.Modules)
	require.Same(t, made[0], built.Modules[len(built.Modules)-1])
	assert.Same(t, built.Queue, made[0].queue)
	assert.True(t, made[0].registered)
}

// Without the mail part nothing would tell anyone a key leaked or an endpoint was turned off, so
// production refuses to start with API keys or outbound webhooks on and no admin notifier.
func TestNoMail_ProductionNeedsAnAdminNotifier(t *testing.T) {
	cfg, err := app.LoadConfig([]string{
		"APP_ENV=test", signingKeys, "APP_REALM_API_HOSTS=api.example.test",
		"APP_WEBHOOKS_OUT_KEYS=a2VlbC10ZXN0LXNpZ25pbmcta2V5LW9mLTMyLWJ5dGVzIQ==",
	})
	require.NoError(t, err)
	parts := app.EnabledParts(cfg)
	if strings.Contains(parts, "mail") || (!strings.Contains(parts, "apikeys") && !strings.Contains(parts, "webhooks")) {
		t.Skip("a build without mail and with API keys or outbound webhooks (go test -tags nomail,nonotes)")
	}
	cfg.Env = config.EnvProduction
	_, err = app.Build(t.Context(), cfg, app.Deps{DB: testdb.Get(t), Notifier: &links{}})
	require.ErrorContains(t, err, "admin notifier")
}
