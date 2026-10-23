package passkey_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/passkey"
	"github.com/PuckxPuck/keel/internal/kit/auth/passkey/passkeytest"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const (
	rpID   = "example.test"
	origin = "https://app.example.test"
	flagUP = passkeytest.FlagUP
	flagUV = passkeytest.FlagUV
)

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

func TestCeremonies(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		rec := audit.New(audit.Options{})
		run := func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
			return db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) })
		}
		svc, err := passkey.New(passkey.Options{Config: passkey.Config{RPID: rpID, Origins: []string{origin}}, DisplayName: "keel", Tx: run, Audit: rec})
		require.NoError(t, err)
		ctx := httpx.WithRealm(t.Context(), "tenant")
		var u users.User
		require.NoError(t, run(ctx, func(ctx context.Context, tx db.Transaction) error {
			u, err = users.NewService(rec, allow{}).Create(ctx, tx, users.NewUser{Email: ids.New().String()[:12] + "@example.test"})
			return err
		}))
		a := passkeytest.New(t, rpID, origin)
		begin := func(fn func(ctx context.Context, tx db.Transaction) (passkey.Challenge, error)) passkey.Challenge {
			var c passkey.Challenge
			require.NoError(t, run(ctx, func(ctx context.Context, tx db.Transaction) error {
				var err error
				c, err = fn(ctx, tx)
				return err
			}))
			return c
		}
		none := func(context.Context, db.Transaction, passkey.Passkey) error { return nil }

		reg := begin(func(ctx context.Context, tx db.Transaction) (passkey.Challenge, error) {
			return svc.BeginRegistration(ctx, tx, u)
		})
		_, err = svc.FinishRegistration(ctx, users.ID(ids.New()), reg.ID, a.Register(t, reg.Options), "Laptop", none)
		require.ErrorIs(t, err, passkey.ErrChallenge, "a challenge made for another user, and now spent")
		reg = begin(func(ctx context.Context, tx db.Transaction) (passkey.Challenge, error) {
			return svc.BeginRegistration(ctx, tx, u)
		})
		laptop, err := svc.FinishRegistration(ctx, u.ID, reg.ID, a.Register(t, reg.Options), "Laptop", none)
		require.NoError(t, err)

		signInOn := func(ctx context.Context, flags byte, count uint32) (users.ID, passkey.Challenge, error) {
			c := begin(svc.BeginSignIn)
			var got users.ID
			err := svc.FinishSignIn(ctx, c.ID, a.Assert(t, c.Options, flags, count), func(_ context.Context, _ db.Transaction, id users.ID) error {
				got = id
				return nil
			})
			return got, c, err
		}
		signIn := func(flags byte, count uint32) (users.ID, passkey.Challenge, error) {
			return signInOn(ctx, flags, count)
		}
		_, _, err = signInOn(httpx.WithRealm(t.Context(), "operator"), flagUP|flagUV, 1)
		require.ErrorIs(t, err, passkey.ErrInvalid, "a passkey works only on the realm it was registered on")
		got, c, err := signIn(flagUP|flagUV, 1)
		require.NoError(t, err)
		assert.Equal(t, u.ID, got)
		err = svc.FinishSignIn(ctx, c.ID, a.Assert(t, c.Options, flagUP|flagUV, 2), func(context.Context, db.Transaction, users.ID) error { return nil })
		require.ErrorIs(t, err, passkey.ErrChallenge, "a challenge works once")

		_, _, err = signIn(flagUP|flagUV, 1)
		require.ErrorIs(t, err, passkey.ErrInvalid, "a sign count that did not move forward")
		_, _, err = signIn(flagUP, 2)
		require.ErrorIs(t, err, passkey.ErrInvalid, "no user verification")
		_, _, err = signIn(flagUP|flagUV, 2)
		require.NoError(t, err, "the refused attempts left the count at 1")

		renamed, err := inTxOf(ctx, run, func(ctx context.Context, tx db.Transaction) (passkey.Passkey, error) {
			return svc.Rename(ctx, tx, u.ID, laptop.ID, laptop.Version, "Work laptop")
		})
		require.NoError(t, err)
		assert.Equal(t, laptop.Version+1, renamed.Version)
		_, err = inTxOf(ctx, run, func(ctx context.Context, tx db.Transaction) (passkey.Passkey, error) {
			return svc.Rename(ctx, tx, u.ID, laptop.ID, laptop.Version, "Old laptop")
		})
		var stale *occ.StaleError
		require.ErrorAs(t, err, &stale)

		lastFactor := func(_ context.Context, _ db.Transaction, kept int) error {
			if kept == 0 {
				return passkey.ErrLastFactor
			}
			return nil
		}
		remove := func(owner users.ID, allow func(context.Context, db.Transaction, int) error) error {
			return run(ctx, func(ctx context.Context, tx db.Transaction) error {
				return svc.Remove(ctx, tx, owner, laptop.ID, allow)
			})
		}
		require.ErrorIs(t, remove(users.ID(ids.New()), nil), passkey.ErrNotFound, "another user's passkey")
		require.ErrorIs(t, remove(u.ID, lastFactor), passkey.ErrLastFactor)
		require.NoError(t, remove(u.ID, nil))
		_, _, err = signIn(flagUP|flagUV, 3)
		require.ErrorIs(t, err, passkey.ErrInvalid, "a removed passkey")
	})
}

func inTxOf[T any](ctx context.Context, run passkey.TxRunner, fn func(ctx context.Context, tx db.Transaction) (T, error)) (T, error) {
	var out T
	err := run(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out, err = fn(ctx, tx)
		return err
	})
	return out, err
}
