//go:build notenancy

package app

import (
	"context"
	"errors"
	"flag"
	"io/fs"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// RealmOperator names the operator realm, which comes with the tenancy part and is not served without it.
const RealmOperator = "operator"

var operatorCatalogue = rbac.NewCatalogue()

type TenancyConfig struct{}

type tenancyWiring struct{}

var errOperatorWithoutTenancy = errors.New("APP_DATABASE_OPERATOR_URL needs the tenancy part: without it nothing may use a role that bypasses row-level security; leave it unset")

func (c Config) validateTenancy() error { return refuseOperator(c) }

// refuseOperator keeps the operator pool closed without the tenancy part, even for a configuration
// that was never validated.
func refuseOperator(c Config) error {
	if c.Database.OperatorURL != "" {
		return errOperatorWithoutTenancy
	}
	return nil
}

func operatorModuleCommands([]string, []Module) []cli.Command { return nil }

func configuredOperator(Config) (realm.Realm, bool) { return realm.Realm{}, false }

func operatorRealms() []realm.Realm { return nil }

func openOptions(Config) []db.OpenOption { return nil }

func startTenancy(ctx context.Context, deps *Deps) error {
	return matchTenancySchema(ctx, deps.DB, false)
}

func checkGlobalTables(fs.FS, db.Dialect) error { return nil }

func allowedMigrations() migrate.Allowed { return migrate.Allowed{} }

func checkMigrated(context.Context, *db.DB) error { return nil }

func (w *wiring) setupTenancy(Config, Deps) error { return nil }

func (w *wiring) sessionTenancy() auth.Tenancy { return nil }

func passThrough(hctx huma.Context, next func(huma.Context)) { next(hctx) }

func (w *wiring) resolveTenant(string, huma.API) func(huma.Context, func(huma.Context)) {
	return passThrough
}

func (w *wiring) guardTenant(string, huma.API, rbac.Principals) func(huma.Context, func(huma.Context)) {
	return passThrough
}

func (w *wiring) memberHere(context.Context, db.Transaction, users.ID) (bool, error) {
	return true, nil
}

func (w *wiring) linkTenant(context.Context, uuid.UUID) (bool, error) { return true, nil }

func (w *wiring) registerTenancy(huma.API) {}

func (w *wiring) registerOperator(huma.API) {}

func tenancyMapper(error) (*problem.Problem, bool) { return nil, false }

func tenancyCommands([]string) []cli.Command { return nil }

func tenantFlag(fs *flag.FlagSet) {
	fs.String("tenant", "", "the tenant's slug (needs the tenancy part)")
}

func inTenant(ctx context.Context, _ Deps, slug string) (context.Context, error) {
	if slug != "" {
		return nil, errors.New("--tenant needs the tenancy part")
	}
	return ctx, nil
}

func joinTenant(context.Context, Deps, string) error { return nil }

func setupOperator(context.Context, Deps, *rbac.Access) (SetupResult, error) {
	return SetupResult{}, nil
}

func queueTx(deps Deps) jobs.TxRunner { return jobs.PlainTx(deps.DB) }

func maintenanceTx(deps Deps) jobs.TxRunner { return jobs.PlainTx(deps.DB) }

//nolint:unused // called by the mail and webhooks parts; an app without both never calls it
func jobTx(deps Deps) jobs.TxRunner { return jobs.PlainTx(deps.DB) }

func eachTenant(ctx context.Context, _ Deps, _ bool, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func grantOperator(context.Context, Deps, *rbac.Access, string, string) error {
	return errors.New("the operator realm needs the tenancy part")
}

func seedTenancy(context.Context, Config, Deps, *audit.Recorder, string, string) error { return nil }

func checkTenancy(ctx context.Context, deps Deps, _ bool) []Check {
	return checkNoTenancy(ctx, deps.DB)
}

func tenancyPart(db.Dialect) bool { return false }
