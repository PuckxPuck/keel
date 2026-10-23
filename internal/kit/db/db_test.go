package db_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/go-jet/jet/v2/qrm"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

func bind(d db.Dialect, n int) string {
	if d == db.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func insertLock(ctx context.Context, tx db.Tx[db.Plain], name string) error {
	_, err := tx.Q().ExecContext(ctx, "INSERT INTO locks (name) VALUES ("+bind(tx.Dialect(), 1)+")", name)
	return err
}

func lockExists(ctx context.Context, t *testing.T, d *db.DB, name string) bool {
	t.Helper()
	var n int
	err := d.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM locks WHERE name = "+bind(d.Dialect(), 1), name).Scan(&n)
	require.NoError(t, err)
	return n == 1
}

func unique(prefix string) string { return prefix + ":" + ids.New().String() }

func TestInTx(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.DB()
		ctx := t.Context()

		t.Run("commits when fn returns nil", func(t *testing.T) {
			name := unique("commit")
			require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return insertLock(ctx, tx, name)
			}))
			assert.True(t, lockExists(ctx, t, d, name))
		})

		t.Run("rolls back when fn fails and skips after-commit hooks", func(t *testing.T) {
			name := unique("rollback")
			ran := false
			boom := errors.New("boom")
			err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				require.NoError(t, db.AfterCommit(ctx, func(context.Context) { ran = true }))
				require.NoError(t, insertLock(ctx, tx, name))
				return boom
			})
			require.ErrorIs(t, err, boom)
			assert.False(t, lockExists(ctx, t, d, name))
			assert.False(t, ran)
		})

		t.Run("rolls back on panic and re-panics", func(t *testing.T) {
			name := unique("panic")
			assert.PanicsWithValue(t, "boom", func() {
				_ = db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
					require.NoError(t, insertLock(ctx, tx, name))
					panic("boom")
				})
			})
			assert.False(t, lockExists(ctx, t, d, name))
		})

		t.Run("after-commit hooks see the committed rows", func(t *testing.T) {
			name := unique("after")
			seen := false
			require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				require.NoError(t, db.AfterCommit(ctx, func(ctx context.Context) { seen = lockExists(ctx, t, d, name) }))
				return insertLock(ctx, tx, name)
			}))
			assert.True(t, seen)
		})

		t.Run("the query handle cannot end the transaction", func(t *testing.T) {
			require.NoError(t, db.InTx(ctx, d, func(_ context.Context, tx db.Tx[db.Plain]) error {
				_, isTx := tx.Q().(*sql.Tx)
				assert.False(t, isTx, "Commit and Rollback belong to InTx")
				return nil
			}))
		})

		t.Run("read-only transactions refuse writes", func(t *testing.T) {
			name := unique("readonly")
			err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return insertLock(ctx, tx, name)
			}, db.ReadOnly())
			require.Error(t, err)
			assert.False(t, lockExists(ctx, t, d, name))
		})

		t.Run("after-commit hooks run when the request is cancelled after commit", func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var hookErr error
			require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, _ db.Tx[db.Plain]) error {
				require.NoError(t, db.AfterCommit(ctx, func(context.Context) { cancel() }))
				return db.AfterCommit(ctx, func(ctx context.Context) { hookErr = ctx.Err() })
			}))
			require.NoError(t, hookErr)
		})

		t.Run("refusals", func(t *testing.T) {
			require.ErrorIs(t, db.AfterCommit(ctx, func(context.Context) {}), db.ErrNoTx)
			err := db.InTx(ctx, d, func(ctx context.Context, _ db.Tx[db.Plain]) error {
				return db.InTx(ctx, d, func(context.Context, db.Tx[db.Plain]) error { return nil })
			})
			require.ErrorIs(t, err, db.ErrNestedTx)
			err = db.InTx(ctx, d, func(context.Context, db.Tx[db.Tenant]) error { return nil })
			require.ErrorIs(t, err, db.ErrTenancyNotConfigured, "tenant transactions fail closed until tenancy sets the tenant")
		})

		t.Run("duplicate keys are unique violations", func(t *testing.T) {
			name := unique("dup")
			err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				require.NoError(t, insertLock(ctx, tx, name))
				return insertLock(ctx, tx, name)
			})
			assert.True(t, db.IsUniqueViolation(err), "got %v", err)
		})
	})
}

func TestTxScopes_DoNotConvert(t *testing.T) {
	scopes := []reflect.Type{reflect.TypeFor[db.Tx[db.Plain]](), reflect.TypeFor[db.Tx[db.Tenant]](), reflect.TypeFor[db.Tx[db.Operator]]()}
	for _, from := range scopes {
		for _, to := range scopes {
			if from != to {
				assert.False(t, from.ConvertibleTo(to), "%s converts to %s", from, to)
			}
		}
	}
}

func TestInTx_Hooks(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		retryable := map[db.Dialect]error{
			db.Postgres: &pgconn.PgError{Code: "40001"},
			db.MySQL:    &mysql.MySQLError{Number: 1213},
		}[e.Dialect()]

		t.Run("before-commit error rolls back", func(t *testing.T) {
			d := db.New(e.Dialect(), e.DB().SQL())
			refused := errors.New("tenant changed")
			db.BeforeCommit[db.Plain](d, func(context.Context, qrm.DB) error { return refused })
			name := unique("before-commit")
			err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return insertLock(ctx, tx, name) })
			require.ErrorIs(t, err, refused)
			assert.False(t, lockExists(ctx, t, d, name))
		})

		t.Run("hooks run on every attempt and only the last attempt's after-commit runs", func(t *testing.T) {
			d := db.New(e.Dialect(), e.DB().SQL())
			var begins, befores, attempts int
			db.OnBegin[db.Plain](d, func(context.Context, qrm.DB) error { begins++; return nil })
			db.BeforeCommit[db.Plain](d, func(context.Context, qrm.DB) error { befores++; return nil })
			var ran []int
			require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, _ db.Tx[db.Plain]) error {
				attempts++
				attempt := attempts
				require.NoError(t, db.AfterCommit(ctx, func(context.Context) { ran = append(ran, attempt) }))
				if attempt < 3 {
					return retryable
				}
				return nil
			}))
			assert.Equal(t, 3, begins)
			assert.Equal(t, 1, befores, "a failed attempt never reaches commit")
			assert.Equal(t, []int{3}, ran)
		})

		t.Run("exhausted retries return the original error", func(t *testing.T) {
			attempts := 0
			err := db.InTx(ctx, e.DB(), func(context.Context, db.Tx[db.Plain]) error {
				attempts++
				return fmt.Errorf("attempt %d: %w", attempts, retryable)
			}, db.Retry(1))
			require.ErrorIs(t, err, retryable)
			assert.Equal(t, "attempt 2: "+retryable.Error(), err.Error())
		})
	})
}

func TestLock_NamesAreExact(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		base := unique("exact")
		require.NoError(t, db.InTx(t.Context(), e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			for _, name := range []string{base + ":Case", base + ":case", base + ":cafe", base + ":caf\u00e9"} {
				if err := db.Lock(ctx, tx, name); err != nil {
					return err
				}
			}
			return nil
		}), "case and accent variants are different locks on both engines")
	})
}

func TestInTx_RetriesDeadlockVictim(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d, ctx := e.DB(), t.Context()
		a, b := unique("deadlock-a"), unique("deadlock-b")
		var attempts atomic.Int32
		var ready sync.WaitGroup
		ready.Add(2)
		work := func(first, second string) error {
			firstAttempt := true
			return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				attempts.Add(1)
				if err := db.Lock(ctx, tx, first); err != nil {
					return err
				}
				if firstAttempt {
					firstAttempt = false
					ready.Done()
					ready.Wait()
				}
				return db.Lock(ctx, tx, second)
			})
		}
		errs := make(chan error, 2)
		go func() { errs <- work(a, b) }()
		go func() { errs <- work(b, a) }()
		require.NoError(t, <-errs)
		require.NoError(t, <-errs)
		assert.Equal(t, int32(3), attempts.Load(), "exactly one transaction is the deadlock victim and runs again")
	})
}

func TestLock_Serialises(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d, ctx := e.DB(), t.Context()
		name := unique("serial")
		var mu sync.Mutex
		var order []string
		record := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

		held, release := make(chan struct{}), make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			errs <- db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				if err := db.Lock(ctx, tx, name); err != nil {
					return err
				}
				close(held)
				<-release
				record("first releases")
				return nil
			})
		}()
		<-held
		go func() {
			errs <- db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				if err := db.Lock(ctx, tx, name); err != nil {
					return err
				}
				record("second holds")
				return nil
			})
		}()
		waitForLockWait(t, e.Owner(t, d))
		close(release)
		require.NoError(t, <-errs)
		require.NoError(t, <-errs)
		assert.Equal(t, []string{"first releases", "second holds"}, order)
	})
}

// waitForLockWait returns once a session in d's database is blocked on a row lock; d must see every
// session's locks (the owner: MySQL's lock tables are beyond the app user's grants).
func waitForLockWait(t *testing.T, d *db.DB) {
	t.Helper()
	query := map[db.Dialect]string{
		db.Postgres: `SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND a.datname = current_database()`,
		db.MySQL: `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
			JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA = DATABASE()`,
	}[d.Dialect()]
	require.Eventually(t, func() bool {
		var n int
		return d.SQL().QueryRowContext(t.Context(), query).Scan(&n) == nil && n > 0
	}, 10*time.Second, 5*time.Millisecond)
}

func TestZeroID_NeverBinds(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		query := map[db.Dialect]string{db.Postgres: "SELECT $1::uuid IS NOT NULL", db.MySQL: "SELECT ? IS NOT NULL"}[e.Dialect()]
		_, err := e.DB().SQL().ExecContext(t.Context(), query, ids.ID[struct{}]{})
		require.ErrorIs(t, err, ids.ErrInvalid, "the driver asks the id for its value, even for a uuid parameter")
		_, err = e.DB().SQL().ExecContext(t.Context(), query, ids.NewOf[struct{}]())
		require.NoError(t, err)
	})
}

func TestSessionRunsInUTC(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		query := map[db.Dialect]string{db.Postgres: "SHOW timezone", db.MySQL: "SELECT @@session.time_zone"}[e.Dialect()]
		var zone string
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), query).Scan(&zone))
		assert.Contains(t, []string{"UTC", "+00:00"}, zone)
	})
}

// Unqualified names resolve in public only: Open pins the search path at startup, ahead of any role or
// database default.
func TestSessionPinsTheSearchPath(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("a Postgres setting")
		}
		var path string
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), "SHOW search_path").Scan(&path))
		assert.Equal(t, "pg_catalog, public", path)
	})
}

func TestOperatorAccess_NeedsTheCapability(t *testing.T) {
	err := db.InOperatorTx(t.Context(), nil, func(context.Context, db.Tx[db.Operator]) error { return nil })
	require.ErrorIs(t, err, db.ErrNoOperatorAccess)
	err = db.InOperatorTx(t.Context(), &db.OperatorAccess{}, func(context.Context, db.Tx[db.Operator]) error { return nil })
	require.ErrorIs(t, err, db.ErrNoOperatorAccess, "a zero capability opens nothing")
}

func TestLikeEscape(t *testing.T) {
	assert.Equal(t, `100\% off\_now \\ here`, db.LikeEscape(`100% off_now \ here`))
}

func TestInsertable_LeavesOutDatabaseFilledColumns(t *testing.T) {
	cols := postgres.ColumnList{
		postgres.StringColumn("tenant_id"), postgres.StringColumn("id"), postgres.StringColumn("name"), postgres.StringColumn("change_xid"),
	}
	var names []string
	for _, c := range db.Insertable(cols) {
		names = append(names, c.Name())
	}
	assert.Equal(t, []string{"id", "name"}, names)
}

func TestConfigValidate(t *testing.T) {
	const secret = "hunter2-secret"
	owner := func(c *db.Config) { c.MigrateURL = config.Secret(strings.Replace(string(c.URL), "app:", "owner:", 1)) }
	tests := []struct {
		name    string
		prod    bool
		mutate  func(*db.Config)
		wantErr string
	}{
		{name: "local without TLS", mutate: func(c *db.Config) { c.URL = "postgres://app:" + secret + "@localhost/app?sslmode=disable" }},
		{name: "production verifies Postgres TLS", prod: true, mutate: func(c *db.Config) {
			c.URL = "postgres://app:" + secret + "@db.internal/app?sslmode=verify-full"
			owner(c)
		}},
		{name: "production verifies MySQL TLS", prod: true, mutate: func(c *db.Config) {
			c.URL = "mysql://app:" + secret + "@db.internal/app?tls=true"
			owner(c)
		}},
		{name: "production serves without the owner's URL", prod: true, mutate: func(c *db.Config) {
			c.URL = "postgres://app:" + secret + "@db.internal/app?sslmode=verify-full"
		}},
		{name: "production refuses migrating as the app role", prod: true, mutate: func(c *db.Config) {
			c.URL = "postgres://app:" + secret + "@db.internal/app?sslmode=verify-full"
			c.MigrateURL = "postgres://app:" + secret + "@db.internal/app?sslmode=verify-full&application_name=migrate"
		}, wantErr: "different role"},
		{name: "production refuses unverified Postgres TLS", prod: true, mutate: func(c *db.Config) {
			c.URL = "postgres://app:" + secret + "@db.internal/app?sslmode=require"
		}, wantErr: "sslmode=verify-full"},
		{name: "production refuses MySQL skip-verify", prod: true, mutate: func(c *db.Config) {
			c.URL = "mysql://app:" + secret + "@db.internal/app?tls=skip-verify"
		}, wantErr: "tls=true"},
		{name: "production needs a URL", prod: true, mutate: func(*db.Config) {}, wantErr: "database URL is required"},
		{name: "operator on another engine", mutate: func(c *db.Config) {
			c.URL = "postgres://app:" + secret + "@localhost/app"
			c.OperatorURL = "mysql://op:" + secret + "@localhost/app"
		}, wantErr: "same database engine"},
		{name: "unknown scheme", mutate: func(c *db.Config) { c.URL = "sqlite://" + secret }, wantErr: "not postgres or mysql"},
		{name: "idle above open", mutate: func(c *db.Config) { c.MaxIdle = 50 }, wantErr: "max idle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := db.Defaults()
			tt.mutate(&cfg)
			err := cfg.Validate(tt.prod)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			assert.NotContains(t, err.Error(), secret, "errors never echo credentials")
		})
	}
}

// A pool acts as the role it logs in as: startup parameters may not switch role (RESET ROLE would return
// to a login nothing checked) or preset an app.* setting. Configuration and Open both refuse them.
func TestStartupParameters_KeepTheLoginRole(t *testing.T) {
	const base = "postgres://app@db.invalid/app?sslmode=disable&"
	tests := []struct {
		name, query string
		operator    bool
		wantErr     string
	}{
		{name: "a role in options", query: "options=-c%20role%3Dkeel_app", wantErr: "startup role"},
		{name: "a role in long options", query: "options=--role%3Dkeel_app", wantErr: "startup role"},
		{name: "a role in joined options", query: "options=-crole%3Dkeel_app", wantErr: "startup role"},
		{name: "a role as a parameter", query: "ROLE=keel_app", wantErr: "startup role"},
		{name: "a session authorization", query: "options=--session-authorization%3Dkeel_app", wantErr: "startup session_authorization"},
		{name: "a tenant setting", query: "app.tenant_id=0190", wantErr: "startup app.tenant_id"},
		{name: "a tenant setting in options", query: "options=-c%20APP.Tenant_ID%3D0190", wantErr: "startup app.tenant_id"},
		{name: "a search path", query: "search_path=shadow,public", wantErr: "startup search_path"},
		{name: "a search path in options", query: "options=-c%20search_path%3Dshadow", wantErr: "startup search_path"},
		{name: "an escaped option", query: "options=-c%5C%20role%3Dx", wantErr: "backslash"},
		{name: "a stray option", query: "options=-B%2010", wantErr: "may only set -c name=value"},
		{name: "the operator pool too", query: "options=-c%20role%3Dkeel_operator", operator: true, wantErr: "startup role"},
		{name: "other settings", query: "options=-c%20work_mem%3D64MB&application_name=api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := db.Defaults()
			cfg.URL, cfg.OperatorURL = base+"application_name=app", "postgres://op@db.invalid/app?sslmode=disable"
			if tt.operator {
				cfg.OperatorURL = config.Secret(string(cfg.OperatorURL) + "&" + tt.query)
			} else {
				cfg.URL = config.Secret(base + tt.query)
			}
			err := cfg.Validate(false)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			_, _, err = db.Open(t.Context(), cfg)
			require.ErrorContains(t, err, tt.wantErr, "Open refuses before connecting")
		})
	}
}

func TestOpenSQL_MySQLURLWithoutUserIsAnError(t *testing.T) {
	_, _, err := db.OpenSQL(t.Context(), "mysql://db.internal/app?tls=true", db.Defaults())
	require.ErrorContains(t, err, "not a valid MySQL URL")
}
