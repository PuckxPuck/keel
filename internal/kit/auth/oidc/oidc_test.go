package oidc_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/oidc"
	"github.com/PuckxPuck/keel/internal/kit/auth/oidc/oidctest"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/oauthstate"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const (
	clientID = "keel-client"
	realm    = "tenant"
)

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

func TestSignIn(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		is := oidctest.New(t)
		rec := audit.New(audit.Options{})
		ctx := httpx.WithRealm(t.Context(), realm)
		svc := func(trusted bool) *oidc.Service {
			s, err := oidc.New(oidc.Options{
				Config:      oidc.Config{Issuer: is.URL, ClientID: clientID, Scopes: []string{"openid", "email"}, EmailTrusted: trusted},
				Realms:      []string{realm},
				RedirectURL: "https://app.example.test/api/v1/auth/oidc/callback", Tx: oauthstate.PlainTx(e.DB()), Audit: rec,
			})
			require.NoError(t, err)
			return s
		}
		inTx := func(fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
			return db.InTx(ctx, e.DB(), fn)
		}
		start := func(s *oidc.Service) oidc.Started {
			st, err := s.Start(ctx, "/after")
			require.NoError(t, err)
			return st
		}
		signIn := func(s *oidc.Service, claims oidc.Claims) (users.ID, error) {
			var id users.ID
			err := inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				id, err = s.Link(ctx, tx, claims)
				return err
			})
			return id, err
		}
		email := ids.New().String()[:12] + "@example.test"
		var ann users.User
		require.NoError(t, inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			ann, err = users.NewService(rec, allow{}).Create(ctx, tx, users.NewUser{Email: email, Name: "Ann"})
			return err
		}))
		subject := ids.New().String()

		t.Run("checks the token and spends the state once", func(t *testing.T) {
			s := svc(false)
			st := start(s)
			assert.Equal(t, oidc.CookieName, st.Cookie.Name)
			state, code := is.Authorise(t, st.URL, subject, email, true, nil)

			_, _, err := s.Finish(ctx, state, "another browser", code)
			require.ErrorIs(t, err, oidc.ErrInvalidState, "the state is bound to the browser that started")
			claims, returnTo, err := s.Finish(ctx, state, st.Cookie.Value, code)
			require.NoError(t, err)
			assert.Equal(t, "/after", returnTo)
			assert.Equal(t, subject, claims.Subject)
			assert.True(t, claims.EmailVerified)
			_, _, err = s.Finish(ctx, state, st.Cookie.Value, code)
			require.ErrorIs(t, err, oidc.ErrInvalidState, "single use")
			_, err = s.Start(httpx.WithRealm(ctx, "operator"), "/after")
			require.ErrorIs(t, err, oidc.ErrNotEnabled, "a realm OIDC is not enabled on")
		})

		refusals := map[string]func(map[string]any){
			"nonce mismatch": func(c map[string]any) { c["nonce"] = "another" },
			"wrong audience": func(c map[string]any) { c["aud"] = "someone-else" },
			"issued later":   func(c map[string]any) { c["iat"] = c["iat"].(int64) + 3600 },
			"expired":        func(c map[string]any) { c["exp"] = c["iat"].(int64) - 60 },
			"other issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		}
		for name, edit := range refusals {
			t.Run(name, func(t *testing.T) {
				s := svc(false)
				st := start(s)
				state, code := is.Authorise(t, st.URL, subject, email, true, edit)
				_, _, err := s.Finish(ctx, state, st.Cookie.Value, code)
				require.ErrorIs(t, err, oidc.ErrToken)
			})
		}

		t.Run("linking needs corroboration", func(t *testing.T) {
			first := oidc.Claims{Issuer: is.URL, Subject: subject, Email: email, EmailVerified: true}
			_, err := signIn(svc(false), first)
			require.ErrorIs(t, err, oidc.ErrRefused, "a provider not trusted for email")
			unverified := first
			unverified.EmailVerified = false
			_, err = signIn(svc(true), unverified)
			require.ErrorIs(t, err, oidc.ErrRefused, "an unverified address")
			stranger := first
			stranger.Subject, stranger.Email = ids.New().String(), "nobody-"+email
			_, err = signIn(svc(true), stranger)
			require.ErrorIs(t, err, oidc.ErrRefused, "no user holds the address")

			id, err := signIn(svc(true), first)
			require.NoError(t, err)
			assert.Equal(t, ann.ID, id)
			moved := first
			moved.Email, moved.EmailVerified = "changed-"+email, false
			id, err = signIn(svc(false), moved)
			require.NoError(t, err, "a linked subject signs in whatever its address says now")
			assert.Equal(t, ann.ID, id)

			recycled := first
			recycled.Subject = ids.New().String()
			_, err = signIn(svc(true), recycled)
			require.ErrorIs(t, err, oidc.ErrRefused, "the provider gave Ann's address to a new subject")
		})

		t.Run("concurrent first sign-ins of one subject both sign in", func(t *testing.T) {
			bob := ids.New().String()[:12] + "@example.test"
			var u users.User
			require.NoError(t, inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				u, err = users.NewService(rec, allow{}).Create(ctx, tx, users.NewUser{Email: bob, Name: "Bob"})
				return err
			}))
			claims := oidc.Claims{Issuer: is.URL, Subject: ids.New().String(), Email: bob, EmailVerified: true}
			linked, release := make(chan struct{}), make(chan struct{})
			var wg sync.WaitGroup
			errs := make([]error, 2)
			wg.Go(func() {
				errs[0] = inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
					_, err := svc(true).Link(ctx, tx, claims)
					close(linked)
					<-release
					return err
				})
			})
			<-linked
			wg.Go(func() {
				var id users.ID
				id, errs[1] = signIn(svc(true), claims)
				if errs[1] == nil && id != u.ID {
					errs[1] = oidc.ErrRefused
				}
			})
			time.Sleep(200 * time.Millisecond)
			close(release)
			wg.Wait()
			require.NoError(t, errs[0])
			require.NoError(t, errs[1], "the second waits for the first link and signs in through it")
		})
	})
}
