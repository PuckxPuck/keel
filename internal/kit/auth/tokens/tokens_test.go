package tokens_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

func TestConsume_SingleUseBoundToPurposeAndExpiry(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
		ctx := clock.WithWall(t.Context(), clock.Fixed(at))
		inTx := func(ctx context.Context, fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
			return db.InTx(ctx, e.DB(), fn)
		}
		var u users.User
		require.NoError(t, inTx(ctx, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			u, err = users.NewService(audit.New(audit.Options{}), allow{}).Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"})
			return err
		}))
		issue := func(p tokens.Purpose) string {
			var raw string
			require.NoError(t, inTx(ctx, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				raw, err = tokens.Issue(ctx, tx, u.ID, p, time.Hour)
				return err
			}))
			return raw
		}
		consume := func(ctx context.Context, raw string, p tokens.Purpose) error {
			return inTx(ctx, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				got, err := tokens.Consume(ctx, tx, raw, p)
				if err == nil {
					assert.Equal(t, u.ID, got)
				}
				return err
			})
		}

		reset := issue(tokens.PasswordReset)
		require.ErrorIs(t, consume(ctx, reset, tokens.Invite), tokens.ErrInvalid, "another purpose")
		require.NoError(t, consume(ctx, reset, tokens.PasswordReset), "a wrong purpose does not spend it")
		require.ErrorIs(t, consume(ctx, reset, tokens.PasswordReset), tokens.ErrInvalid, "single use")

		verify := issue(tokens.VerifyEmail)
		later := clock.WithWall(t.Context(), clock.Fixed(at.Add(time.Hour)))
		require.ErrorIs(t, consume(later, verify, tokens.VerifyEmail), tokens.ErrInvalid, "expired")

		first, second := issue(tokens.Invite), issue(tokens.Invite)
		require.ErrorIs(t, consume(ctx, first, tokens.Invite), tokens.ErrInvalid, "a newer link retires the older one")
		require.NoError(t, consume(ctx, second, tokens.Invite))

		require.ErrorIs(t, consume(ctx, "not-a-token", tokens.Invite), tokens.ErrInvalid)
	})
}

// Links issued at once leave exactly one that works, and a link spent at once works exactly once.
func TestIssueAndConsume_Concurrent(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		var u users.User
		require.NoError(t, db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			u, err = users.NewService(audit.New(audit.Options{}), allow{}).Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"})
			return err
		}))
		const n = 4
		run := func(fn func(ctx context.Context, tx db.Tx[db.Plain]) error) []error {
			errs := make([]error, n)
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					errs[i] = db.InTx(ctx, e.DB(), fn)
				})
			}
			wg.Wait()
			return errs
		}
		var mu sync.Mutex
		var issued []string
		for _, err := range run(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			raw, err := tokens.Issue(ctx, tx, u.ID, tokens.PasswordReset, time.Hour)
			if err == nil {
				mu.Lock()
				defer mu.Unlock()
				issued = append(issued, raw)
			}
			return err
		}) {
			require.NoError(t, err)
		}
		spent := 0
		for _, raw := range issued {
			if db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				_, err := tokens.Consume(ctx, tx, raw, tokens.PasswordReset)
				return err
			}) == nil {
				spent++
			}
		}
		assert.Equal(t, 1, spent, "only the last link issued works")

		var raw string
		require.NoError(t, db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			raw, err = tokens.Issue(ctx, tx, u.ID, tokens.Invite, time.Hour)
			return err
		}))
		used := 0
		for _, err := range run(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			_, err := tokens.Consume(ctx, tx, raw, tokens.Invite)
			return err
		}) {
			if err == nil {
				used++
				continue
			}
			require.ErrorIs(t, err, tokens.ErrInvalid)
		}
		assert.Equal(t, 1, used)
	})
}
