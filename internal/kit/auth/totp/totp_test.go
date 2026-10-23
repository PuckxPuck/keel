package totp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/totp"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
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

var at = time.Date(2026, 10, 22, 9, 0, 10, 0, time.UTC)

func codeAt(t *testing.T, secret string, when time.Time) string {
	t.Helper()
	c, err := otptotp.GenerateCodeCustom(secret, when, otptotp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	return c
}

type fixture struct {
	e    *testdb.Engine
	rec  *audit.Recorder
	user users.User
}

func (f fixture) inTx(ctx context.Context, fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
	return db.InTx(ctx, f.e.DB(), fn)
}

func newFixture(t *testing.T, e *testdb.Engine) fixture {
	t.Helper()
	f := fixture{e: e, rec: audit.New(audit.Options{})}
	require.NoError(t, f.inTx(t.Context(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		f.user, err = users.NewService(f.rec, allow{}).Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"})
		return err
	}))
	return f
}

// enrol sets up and confirms an authenticator with svc at the fixed time and returns its secret and
// recovery codes.
func (f fixture) enrol(t *testing.T, svc *totp.Service) (string, []string) {
	t.Helper()
	ctx := clock.WithWall(t.Context(), clock.Fixed(at))
	var secret string
	var codes []string
	require.NoError(t, f.inTx(ctx, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		en, err := svc.Enrol(ctx, tx, f.user)
		secret = en.Secret
		return err
	}))
	require.NoError(t, f.inTx(ctx, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		codes, err = svc.Confirm(ctx, tx, f.user.ID, codeAt(t, secret, at))
		return err
	}))
	return secret, codes
}

func newService(t *testing.T, rec *audit.Recorder, keys ...config.Secret) *totp.Service {
	t.Helper()
	svc, err := totp.New(keys, "keel", rec)
	require.NoError(t, err)
	return svc
}

func TestVerify_EachStepOnceWithOneStepOfSkew(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		f := newFixture(t, e)
		svc := newService(t, f.rec, "key-one")
		secret, _ := f.enrol(t, svc)
		verify := func(now time.Time, code string) error {
			return f.inTx(clock.WithWall(t.Context(), clock.Fixed(now)), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return svc.Verify(ctx, tx, f.user.ID, code)
			})
		}
		next := at.Add(30 * time.Second)

		require.ErrorIs(t, verify(at, codeAt(t, secret, at)), totp.ErrInvalidCode, "the confirming code cannot be replayed")
		require.NoError(t, verify(at, codeAt(t, secret, next)), "one step ahead is accepted")
		require.ErrorIs(t, verify(next, codeAt(t, secret, next)), totp.ErrInvalidCode, "replay of a used step")
		require.ErrorIs(t, verify(at.Add(2*time.Minute), codeAt(t, secret, at.Add(4*time.Minute))), totp.ErrInvalidCode, "too far ahead")
		require.NoError(t, verify(at.Add(2*time.Minute), codeAt(t, secret, at.Add(90*time.Second))), "one step behind is accepted")
	})
}

func TestUseRecovery_EachCodeOnce(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		f := newFixture(t, e)
		svc := newService(t, f.rec, "key-one")
		_, codes := f.enrol(t, svc)
		require.Len(t, codes, 10)
		use := func(code string) error {
			return f.inTx(t.Context(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return svc.UseRecovery(ctx, tx, f.user.ID, code)
			})
		}

		require.NoError(t, use(codes[3]))
		require.ErrorIs(t, use(codes[3]), totp.ErrInvalidCode, "used once already")
		used := 0
		for _, err := range concurrently(4, func() error { return use(codes[5]) }) {
			if err == nil {
				used++
				continue
			}
			require.ErrorIs(t, err, totp.ErrInvalidCode)
		}
		assert.Equal(t, 1, used, "a code spent at once works once")
		require.NoError(t, use(" "+codes[4][:9]+codes[4][10:]+" "), "dashes and spaces do not matter")
		require.ErrorIs(t, use("aaaa-bbbb-cccc-dddd"), totp.ErrInvalidCode)
	})
}

func concurrently(n int, fn func() error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = fn() })
	}
	wg.Wait()
	return errs
}

// Two first enrolments at once both start one (the later secret wins); a confirmed one is never replaced.
func TestEnrol_Concurrent(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		f := newFixture(t, e)
		svc := newService(t, f.rec, "key-one")
		for _, err := range concurrently(4, func() error {
			return f.inTx(t.Context(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				_, err := svc.Enrol(ctx, tx, f.user)
				return err
			})
		}) {
			require.NoError(t, err)
		}
		f.enrol(t, svc)
		err := f.inTx(t.Context(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			_, err := svc.Enrol(ctx, tx, f.user)
			return err
		})
		require.ErrorIs(t, err, totp.ErrAlreadyEnrolled)
	})
}

// Secrets are sealed with the newest key; an older key still opens them and the next use reseals.
func TestKeys_RotateWithoutReenrolling(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		f := newFixture(t, e)
		secret, _ := f.enrol(t, newService(t, f.rec, "old-key"))
		sealed := func() []byte {
			var b []byte
			require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), db.Rebind(e.Dialect(), "SELECT secret_enc FROM mfa_totp WHERE user_id = ?"), f.user.ID).Scan(&b))
			return b
		}
		before := sealed()
		rotated := newService(t, f.rec, "new-key", "old-key")
		now := at.Add(time.Minute)

		require.NoError(t, f.inTx(clock.WithWall(t.Context(), clock.Fixed(now)), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return rotated.Verify(ctx, tx, f.user.ID, codeAt(t, secret, now))
		}))
		assert.NotEqual(t, before, sealed(), "resealed with the newest key")

		later := now.Add(time.Minute)
		require.NoError(t, f.inTx(clock.WithWall(t.Context(), clock.Fixed(later)), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return newService(t, f.rec, "new-key").Verify(ctx, tx, f.user.ID, codeAt(t, secret, later))
		}), "the old key is no longer needed")
	})
}
