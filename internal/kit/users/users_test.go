package users_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
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

type actor users.ID

func (a actor) ActingUser() (users.ID, bool) { return users.ID(a), true }

func TestNormaliseEmail(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"  Ann.Lee@Example.COM ", "ann.lee@example.com", true},
		{"JOSÉ@example.com", "josé@example.com", true},
		{"ann@example", "", false},
		{"ann@@example.com", "", false},
		{"@example.com", "", false},
		{"ann lee@example.com", "", false},
		{"ann@example.com.", "", false},
		{"ann\x00@example.com", "", false},
		{"ann\xff@example.com", "", false},
		{strings.Repeat("a", 250) + "@example.com", "", false},
	}
	for _, tt := range tests {
		got, err := users.NormaliseEmail(tt.in)
		if !tt.ok {
			require.ErrorIs(t, err, users.ErrInvalidEmail, tt.in)
			continue
		}
		require.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got)
	}
}

func TestService(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		svc := users.NewService(audit.New(audit.Options{}), allow{})
		local := ids.New().String()[:12]
		inTx := func(fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
			return db.InTx(ctx, e.DB(), fn)
		}
		create := func(email string) (users.User, error) {
			var u users.User
			err := inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				u, err = svc.Create(ctx, tx, users.NewUser{Email: email, Name: "Ann"})
				return err
			})
			return u, err
		}
		jose, err := create("jose" + local + "@Example.test")
		require.NoError(t, err)
		accented, err := create("josé" + local + "@example.test")
		require.NoError(t, err, "an accent makes another address on both engines")

		t.Run("email is one identity in any letter case or Unicode form, and no other", func(t *testing.T) {
			for _, taken := range []string{"JOSE" + local + "@EXAMPLE.TEST", "JOSÉ" + strings.ToUpper(local) + "@example.test"} {
				_, err := create(taken)
				require.ErrorIs(t, err, users.ErrEmailTaken, taken)
			}
			for email, want := range map[string]users.ID{
				"Jose" + local + "@example.TEST":        jose.ID,
				"JOSÉ" + local + "@example.test":        accented.ID,
				"josé" + local + "@example.test":       accented.ID,
				"josè" + local + "@example.test":        {},
				"joße" + local + "@example.test":        {},
				"jose" + local + "@example.test.":       {},
				"jose" + local + "@example.test\u0000x": {},
			} {
				require.NoError(t, inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
					found, err := users.ByEmail(ctx, tx, email)
					if want.IsZero() {
						assert.ErrorIs(t, err, users.ErrNotFound, email)
						return nil
					}
					assert.Equal(t, want, found.ID, email)
					return err
				}))
			}
		})

		t.Run("a stale version is refused with the current version, who and when", func(t *testing.T) {
			u, err := create(ids.New().String() + "@example.test")
			require.NoError(t, err)
			editor, err := create(ids.New().String() + "@example.test")
			require.NoError(t, err)
			read, committed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			go func() {
				<-read
				assert.NoError(t, inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
					_, err := svc.SetStatus(ctx, tx, actor(editor.ID), u.ID, u.Version, users.Disabled)
					return err
				}))
				close(committed)
			}()
			err = inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
				// An earlier read fixes MySQL's snapshot before the other change commits.
				if _, err := users.Get(ctx, tx, u.ID); err != nil {
					return err
				}
				once.Do(func() { close(read); <-committed })
				_, err := svc.SetStatus(ctx, tx, actor(editor.ID), u.ID, u.Version, users.Active)
				return err
			})
			var stale *occ.StaleError
			require.ErrorAs(t, err, &stale)
			assert.Equal(t, u.Version+1, stale.Current.Version)
			require.NotNil(t, stale.Current.ChangedBy)
			assert.Equal(t, editor.ID.UUID(), *stale.Current.ChangedBy)

			p, ok := occ.Mapper(err)
			require.True(t, ok)
			assert.Equal(t, http.StatusConflict, p.Status)
			assert.Equal(t, occ.CodeStaleVersion, p.Code)
		})

		t.Run("a missing user is not found, not stale", func(t *testing.T) {
			err := inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
				_, err := svc.SetStatus(ctx, tx, actor(jose.ID), users.ID(ids.New()), 1, users.Disabled)
				return err
			})
			assert.ErrorIs(t, err, users.ErrNotFound)
		})
	})
}
