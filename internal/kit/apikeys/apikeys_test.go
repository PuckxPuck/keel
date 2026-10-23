package apikeys_test

import (
	"context"
	"encoding/base64"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/apikeys"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const (
	manage   rbac.Code = "api_keys.manage"
	read     rbac.Code = "orders.read"
	write    rbac.Code = "orders.write"
	adminAll rbac.Code = "access.manage"
)

var catalogue = rbac.NewCatalogue(
	rbac.Perm{Code: manage}, rbac.Perm{Code: adminAll},
	rbac.Perm{Code: read, APIGrantable: true}, rbac.Perm{Code: write, APIGrantable: true},
)

var at = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

func service(t *testing.T) *apikeys.Service {
	t.Helper()
	s, err := apikeys.New(apikeys.Options{
		Format: apikeys.Format{Prefix: "myapp", Env: apikeys.EnvTest}, Realm: "api", Catalogue: catalogue, Manage: manage, Audit: audit.New(audit.Options{}),
	})
	require.NoError(t, err)
	return s
}

func inTx(t *testing.T, e *testdb.Engine, when time.Time, fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
	t.Helper()
	return db.InTx(clock.WithWall(t.Context(), clock.Fixed(when)), e.DB(), fn)
}

func TestCreate_ScopesAreGrantableAndHeldByTheCreator(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		svc := service(t)
		reader := rbac.NewPrincipal(users.ID(ids.New()), "tenant", rbac.Grant{Perm: manage}, rbac.Grant{Perm: read})
		tests := []struct {
			name   string
			actor  rbac.Principal
			scopes []rbac.Code
			rule   string
		}{
			{"a scope the creator lacks", reader, []rbac.Code{read, write}, rbac.RuleExceedsActor},
			{"a permission never given to keys", reader, []rbac.Code{adminAll}, apikeys.RuleNotGrantable},
			{"not even by the system", rbac.System("tenant"), []rbac.Code{manage}, apikeys.RuleNotGrantable},
			{"an unknown code", rbac.System("tenant"), []rbac.Code{"orders.delete"}, rbac.RuleUnknownPermission},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
					_, _, err := svc.Create(ctx, tx, tt.actor, apikeys.NewKey{Name: "Plugin", Scopes: tt.scopes})
					return err
				})
				var refused *rbac.RefusedError
				require.ErrorAs(t, err, &refused)
				require.Len(t, refused.Violations, 1)
				assert.Equal(t, tt.rule, refused.Violations[0].Rule)
			})
		}
		err := inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			_, _, err := svc.Create(ctx, tx, rbac.NewPrincipal(users.ID(ids.New()), "tenant", rbac.Grant{Perm: read}), apikeys.NewKey{Name: "Plugin"})
			return err
		})
		require.ErrorIs(t, err, rbac.ErrForbidden, "creating needs the manage permission")
	})
}

func TestResolve_RevocationExpiryAndAllowlistApplyOnTheNextRequest(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		svc := service(t)
		office := netip.MustParseAddr("203.0.113.7")
		create := func(in apikeys.NewKey) (string, apikeys.Key) {
			var plain string
			var k apikeys.Key
			require.NoError(t, inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				plain, k, err = svc.Create(ctx, tx, rbac.System("tenant"), in)
				return err
			}))
			return plain, k
		}
		resolve := func(when time.Time, raw string, from netip.Addr) (apikeys.Resolved, error) {
			var got apikeys.Resolved
			err := inTx(t, e, when, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				got, err = svc.Resolve(ctx, tx, raw, from)
				return err
			})
			return got, err
		}

		expires := at.Add(time.Hour)
		plain, k := create(apikeys.NewKey{Name: "Plugin", Scopes: []rbac.Code{read}, ExpiresAt: &expires, AllowedCIDRs: []string{"203.0.113.0/24"}})
		got, err := resolve(at, plain, office)
		require.NoError(t, err)
		assert.Equal(t, rbac.SubjectAPIKey, got.Principal.Kind())
		assert.Equal(t, k.ID.UUID(), got.Principal.Subject())
		assert.True(t, got.Principal.Can(read))
		assert.False(t, got.Principal.Can(write))

		_, err = resolve(at, plain, netip.MustParseAddr("198.51.100.1"))
		require.ErrorIs(t, err, apikeys.ErrInvalidKey, "outside the allowlist")
		_, err = resolve(expires, plain, office)
		require.ErrorIs(t, err, apikeys.ErrInvalidKey, "expired")

		require.NoError(t, inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return svc.Revoke(ctx, tx, rbac.System("tenant"), k.ID)
		}))
		_, err = resolve(at, plain, office)
		require.ErrorIs(t, err, apikeys.ErrInvalidKey, "revoked, on the very next request")

		_, other := create(apikeys.NewKey{Name: "Other"})
		_, err = resolve(at, svc.Format().NewKeyFor(other.ID.UUID()), office)
		require.ErrorIs(t, err, apikeys.ErrInvalidKey, "the right id and checksum with another secret")
	})
}

// A request never waits on another transaction that holds the key's row (a revoke, a reminder job).
func TestResolve_RecordingUseNeverWaitsOnARowLock(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		svc := service(t)
		var plain string
		var k apikeys.Key
		require.NoError(t, inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			plain, k, err = svc.Create(ctx, tx, rbac.System("tenant"), apikeys.NewKey{Name: "Plugin"})
			return err
		}))
		holder, err := e.DB().SQL().BeginTx(t.Context(), nil)
		require.NoError(t, err)
		defer func() { _ = holder.Rollback() }()
		_, err = holder.ExecContext(t.Context(), db.Rebind(e.DB().Dialect(), "UPDATE api_keys SET name = name WHERE id = ?"), k.ID)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(clock.WithWall(t.Context(), clock.Fixed(at)), 3*time.Second)
		defer cancel()
		err = db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			_, err := svc.Resolve(ctx, tx, plain, netip.Addr{})
			return err
		})
		require.NoError(t, err)
	})
}

// Only the report that revokes a key alerts: a replayed delivery changes nothing, and a second partner
// report racing the first waits for it and is recorded as a re-report.
func TestReportLeaks_OnlyTheRevokingReportAlerts(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		var alerts atomic.Int32
		revoking, release := make(chan struct{}), make(chan struct{})
		svc, err := apikeys.New(apikeys.Options{
			Format: apikeys.Format{Prefix: "myapp", Env: apikeys.EnvTest}, Realm: "api", Catalogue: catalogue, Manage: manage,
			Audit: audit.New(audit.Options{}),
			OnLeak: func(context.Context, db.Transaction, apikeys.Key, apikeys.Leak) error {
				if alerts.Add(1) == 1 {
					close(revoking)
					<-release
				}
				return nil
			},
		})
		require.NoError(t, err)
		verifier, err := webhook.NewVerifier(webhook.Options{
			Source: "apikey-leaks", Secrets: []string{"whsec_" + base64.StdEncoding.EncodeToString([]byte("keel-test-leak-report-key-32-byte"))},
		})
		require.NoError(t, err)
		var plain string
		require.NoError(t, inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			plain, _, err = svc.Create(ctx, tx, rbac.System("tenant"), apikeys.NewKey{Name: "Plugin"})
			return err
		}))
		report := func(delivery string) error {
			return inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				replayed, err := verifier.Seen(ctx, tx, delivery)
				if err != nil {
					return err
				}
				got, err := svc.ReportLeaks(ctx, tx, []apikeys.Leak{{Token: plain}}, replayed)
				if err == nil && got[0].Label != apikeys.TruePositive {
					t.Errorf("delivery %s answered %s", delivery, got[0].Label)
				}
				return err
			})
		}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Go(func() { errs[0] = report("msg_first") })
		<-revoking
		wg.Go(func() { errs[1] = report("msg_second") })
		time.Sleep(200 * time.Millisecond)
		close(release)
		wg.Wait()
		require.NoError(t, errs[0])
		require.NoError(t, errs[1])
		require.NoError(t, report("msg_first"), "a replay")
		assert.Equal(t, int32(1), alerts.Load())
	})
}

func TestDueForReminder_EachWindowOnce(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		svc := service(t)
		expires := at.Add(20 * 24 * time.Hour)
		var k apikeys.Key
		require.NoError(t, inTx(t, e, at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			_, k, err = svc.Create(ctx, tx, rbac.System("tenant"), apikeys.NewKey{Name: "Expiring", ExpiresAt: &expires})
			return err
		}))
		due := func(when time.Time, within time.Duration) bool {
			var keys []apikeys.Key
			require.NoError(t, inTx(t, e, when, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				keys, err = apikeys.DueForReminder(ctx, tx, within)
				return err
			}))
			for _, got := range keys {
				if got.ID == k.ID {
					return true
				}
			}
			return false
		}
		remind := func(when time.Time) {
			require.NoError(t, inTx(t, e, when, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return apikeys.MarkReminded(ctx, tx, k.ID)
			}))
		}
		twoWeeks, day := 14*24*time.Hour, 24*time.Hour
		assert.False(t, due(at, twoWeeks), "too early")
		first := expires.Add(-twoWeeks + time.Hour)
		require.True(t, due(first, twoWeeks))
		remind(first)
		assert.False(t, due(first.Add(day), twoWeeks), "already reminded in this window")
		last := expires.Add(-day + time.Hour)
		require.True(t, due(last, day), "the one-day window is new")
		remind(last)
		assert.False(t, due(last, day))
	})
}
