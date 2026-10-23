package app

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func seedFlags(fs *flag.FlagSet) {
	fs.String("email", "admin@example.test", "the administrator to create")
	fs.String("tenant", "local", "the tenant's slug (tenancy)")
}

// dbSeed makes local development data: the built-in roles, an administrator who can sign in with dev
// login, and under tenancy a tenant they own and the operator role. It runs again without harm.
func dbSeed(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		if cfg.Env != config.EnvLocal {
			return errors.New("db:seed runs only with APP_ENV=local")
		}
		email := flagValue(fs, "email")
		if err := Seed(ctx, cfg, deps, email, flagValue(fs, "tenant")); err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "seeded %s; sign in with POST %s/auth/dev-login\n", email, BasePath)
		return err
	}
}

// Seed creates the local administrator with email and gives them the administrator role (under
// tenancy: a tenant with slug that they own, and the operator role).
func Seed(ctx context.Context, cfg Config, deps Deps, email, slug string) error {
	rec := audit.New(audit.Options{Chain: cfg.Audit.Chain})
	if _, err := Setup(ctx, deps, rec); err != nil {
		return err
	}
	w, err := newWiring(cfg, deps)
	if err != nil {
		return err
	}
	err = db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
		if _, err := users.ByEmail(ctx, tx, email); !errors.Is(err, users.ErrNotFound) {
			return err
		}
		_, err := w.users().Create(ctx, tx, users.NewUser{Email: email, Name: "Administrator"})
		return err
	})
	if err != nil {
		return err
	}
	if deps.Tenancy {
		return seedTenancy(ctx, cfg, deps, rec, email, slug)
	}
	return alreadyGranted(GrantRole(ctx, deps, rec, RealmTenant, ownerRoleCode, email, ""))
}

// ownerRoleCode is the built-in role the seeded administrator holds.
const ownerRoleCode = "admin"

func alreadyGranted(err error) error {
	if errors.Is(err, rbac.ErrAlreadyGranted) {
		return nil
	}
	return err
}
