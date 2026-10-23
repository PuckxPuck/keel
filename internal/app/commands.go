package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

const Name = "app"

type runFunc = func(ctx context.Context, fs *flag.FlagSet, args []string) error

const invalidConfig = "invalid (run config:check)"

func Commands(environ []string) []cli.Command {
	commands := []cli.Command{
		{Name: "serve", Summary: "Run the HTTP API", Run: serve(environ)},
		{Name: "about", Summary: "Show version, environment and enabled parts", Flags: cli.JSONFlag, Run: about(environ)},
		{Name: "config:check", Summary: "Validate configuration and print it with secrets redacted", Flags: cli.JSONFlag, Run: configCheck(environ)},
		{Name: "migrate", Summary: "Apply pending migrations as the owner role", Flags: cli.JSONFlag, Run: migrateUp(environ)},
		{Name: "migrate:status", Summary: "List migrations and whether each is applied", Flags: cli.JSONFlag, Run: migrateStatus(environ)},
		{Name: "migrate:validate", Summary: "Check migration files: names, Up and Down, one statement on MySQL, contract changes", Run: migrateValidate},
		{Name: "migrate:down", Summary: "Roll back the latest migration (refused in production and staging)", Flags: cli.JSONFlag, Run: migrateDown(environ)},
		{Name: "db:seed", Summary: "Local only: a signed-in-ready administrator (and tenant) for development", Flags: seedFlags, Run: dbSeed(environ)},
		{Name: "setup", Summary: "Create missing built-in roles and add new permissions to existing ones; safe on every deploy", Flags: cli.JSONFlag, Run: setup(environ)},
		{Name: "doctor", Summary: "Check configuration, database, roles, queues, mail, files and keys", Flags: cli.JSONFlag, Run: doctor(environ)},
		{Name: "route:list", Summary: "List every operation with its realm, Need and rate-limit class", Flags: cli.JSONFlag, Run: routeList},
		{Name: "permission:list", Summary: "List the permission catalogue per realm and the built-in roles holding each", Flags: cli.JSONFlag, Run: permissionList},
		{Name: "user:create", Summary: "Create a user and send them an invite", Flags: userCreateFlags, Run: userCreate(environ)},
		{Name: "user:grant", Summary: "Give a user a role as the system (first administrator, incidents)", Flags: userGrantFlags, Run: userGrant(environ)},
		{Name: "user:revoke-sessions", Summary: "Sign a user out everywhere", Run: userRevokeSessions(environ)},
	}
	commands = append(commands, apiKeyCommands(environ)...)
	commands = append(commands, tenancyCommands(environ)...)
	commands = append(commands, jobs.Commands(openQueue(environ))...)
	commands = append(commands, webhookCommands(environ)...)
	commands = append(commands, connectionCommands(environ)...)
	return append(commands, cli.Command{Name: "openapi", Summary: "Print a realm's OpenAPI document (--realm api for the public API)", Flags: openAPIFlags, Run: openAPI})
}

// openAssembled loads the configuration, opens the database and wires every service, as serve does.
func openAssembled(ctx context.Context, environ []string) (*wiring, func(), error) {
	cfg, deps, err := openForCommand(ctx, environ)
	if err != nil {
		return nil, nil, err
	}
	w, err := assemble(ctx, cfg, deps)
	if err != nil {
		_ = deps.DB.Close()
		return nil, nil, err
	}
	return w, func() { _ = deps.DB.Close() }, nil
}

// openQueue gives the queue commands (worker and queue:work among them) the queue serve runs: every kind
// and schedule registered.
func openQueue(environ []string) jobs.Opener {
	return func(ctx context.Context) (*jobs.Queue, func(), error) {
		w, done, err := openAssembled(ctx, environ)
		if err != nil {
			return nil, nil, err
		}
		stopOtel, err := startOtel(ctx, w.cfg)
		if err != nil {
			done()
			return nil, nil, err
		}
		return w.queue, func() {
			flushOtel(ctx, stopOtel)
			done()
		}, nil
	}
}

func about(environ []string) runFunc {
	return func(_ context.Context, fs *flag.FlagSet, _ []string) error {
		info := buildinfo.Get()
		env, parts, realmNames := invalidConfig, invalidConfig, invalidConfig
		if cfg, err := LoadConfig(environ); err == nil {
			env, parts = string(cfg.Env), enabledParts(cfg)
			var names []string
			for _, r := range append(configuredRealms(cfg), apiRealms(cfg)...) {
				names = append(names, r.Name)
			}
			realmNames = strings.Join(names, ",")
		}
		return cli.Print(fs.Output(), cli.WantsJSON(fs), cli.Table{
			Columns: []string{"key", "value"},
			Rows: [][]string{
				{"version", info.Version},
				{"commit", info.Commit},
				{"build_time", info.BuildTime},
				{"go_version", info.GoVersion},
				{"env", env},
				{"parts", parts},
				{"realms", realmNames},
			},
		})
	}
}

// enabledParts names the optional parts this build and configuration turn on.
func enabledParts(cfg Config) string {
	var out []string
	if d, err := db.DialectOf(string(cfg.Database.URL)); err == nil {
		out = append(out, string(d))
		if tenancyPart(d) {
			out = append(out, "tenancy")
		}
	}
	out = append(out, "jobs")
	for _, parts := range [][]string{
		mailParts(cfg), filesParts(cfg), pdfParts(cfg), webhookParts(cfg), connectionParts(cfg),
		apiKeyParts(cfg), oidcParts(cfg), passkeyParts(cfg), otelParts(cfg),
	} {
		out = append(out, parts...)
	}
	return strings.Join(out, ",")
}

func openAPIFlags(fs *flag.FlagSet) {
	fs.String("realm", RealmTenant, "realm whose document to print, for example tenant, operator or api")
}

// openAPI prints a realm's OpenAPI document as YAML; it needs no configuration.
func openAPI(_ context.Context, fs *flag.FlagSet, _ []string) error {
	name := flagValue(fs, "realm")
	set, err := Operations()
	if err != nil {
		return err
	}
	api := set.API(name)
	if api == nil {
		return cli.Usagef("unknown realm %q", name)
	}
	doc, err := api.OpenAPI().YAML()
	if err != nil {
		return err
	}
	_, err = fs.Output().Write(doc)
	return err
}

func flagValue(fs *flag.FlagSet, name string) string {
	return strings.TrimSpace(fs.Lookup(name).Value.String())
}

func stamp(t *time.Time) string { //nolint:unused // used by the apikeys and tenancy parts
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func configCheck(environ []string) runFunc {
	return func(_ context.Context, fs *flag.FlagSet, _ []string) error {
		cfg, err := LoadConfig(environ)
		if err != nil {
			return errors.New("invalid configuration:\n" + err.Error())
		}
		table := cli.Table{Columns: []string{"variable", "value"}}
		for _, e := range config.Describe(EnvPrefix, cfg) {
			table.Rows = append(table.Rows, []string{e.Key, e.Value})
		}
		return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
	}
}

// migrateConfig is the part of the configuration migrations read: the environment and the database
// settings they use, so a deploy can hand migrate the owner's URL and nothing else.
type migrateConfig struct {
	Env      config.Env      `env:"ENV,required,notEmpty"`
	Database migrateDatabase `envPrefix:"DATABASE_"`
}

type migrateDatabase struct {
	URL         config.Secret `env:"URL"`
	MigrateURL  config.Secret `env:"MIGRATE_URL"`
	CAFile      string        `env:"CA_FILE"`
	LockTimeout time.Duration `env:"LOCK_TIMEOUT" envDefault:"10s"`
}

func (m migrateDatabase) config() db.Config {
	c := db.Defaults()
	c.URL, c.MigrateURL, c.CAFile, c.LockTimeout = m.URL, m.MigrateURL, m.CAFile, m.LockTimeout
	return c
}

func (m migrateDatabase) Validate(prod bool) error { return m.config().ValidateMigrate(prod) }

// withMigrator connects with the migrate URL (the owner role) and no statement timeout, since DDL on a
// large table may run long; the lock timeout still applies so a blocked migration fails instead of
// queueing every query behind it.
func withMigrator(ctx context.Context, environ []string, fn func(*migrate.Migrator, *db.DB) error) error {
	cfg, err := config.LoadFrom[migrateConfig](EnvPrefix, environ)
	if err != nil {
		return errors.New("invalid database configuration:\n" + err.Error())
	}
	target := cfg.Database.config().MigrateTarget()
	conn := cfg.Database.config()
	conn.StatementTimeout, conn.MaxOpen, conn.MaxIdle = 0, 2, 2
	pool, dialect, err := db.OpenSQL(ctx, target, conn)
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()
	fsys, err := migrations.For(dialect)
	if err != nil {
		return err
	}
	return fn(migrate.New(pool, dialect, fsys, migrate.Options{Production: cfg.Env.IsProd()}), db.New(dialect, pool))
}

func resultsTable(results []migrate.Result) cli.Table {
	table := cli.Table{Columns: []string{"version", "migration", "duration"}}
	for _, r := range results {
		table.Rows = append(table.Rows, []string{strconv.FormatInt(r.Version, 10), r.Name, r.Duration.Round(time.Millisecond).String()})
	}
	return table
}

func migrateUp(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		return withMigrator(ctx, environ, func(m *migrate.Migrator, d *db.DB) error {
			results, err := m.Up(ctx)
			if printErr := cli.Print(fs.Output(), cli.WantsJSON(fs), resultsTable(results)); printErr != nil {
				return errors.Join(err, printErr)
			}
			if err != nil {
				return err
			}
			return checkMigrated(ctx, d)
		})
	}
}

func migrateDown(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		return withMigrator(ctx, environ, func(m *migrate.Migrator, _ *db.DB) error {
			r, err := m.Down(ctx)
			if err != nil {
				return err
			}
			return cli.Print(fs.Output(), cli.WantsJSON(fs), resultsTable([]migrate.Result{r}))
		})
	}
}

func migrateStatus(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		return withMigrator(ctx, environ, func(m *migrate.Migrator, _ *db.DB) error {
			statuses, err := m.Status(ctx)
			if err != nil {
				return err
			}
			table := cli.Table{Columns: []string{"version", "migration", "applied_at"}}
			for _, s := range statuses {
				at := "pending"
				if s.Applied {
					at = s.AppliedAt.UTC().Format(time.RFC3339)
				}
				table.Rows = append(table.Rows, []string{strconv.FormatInt(s.Version, 10), s.Name, at})
			}
			return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
		})
	}
}

// migrateValidate checks every dialect's directory and needs no configuration or database.
func migrateValidate(_ context.Context, fset *flag.FlagSet, _ []string) error {
	var errs []error
	for _, d := range []db.Dialect{db.Postgres, db.MySQL} {
		fsys, err := migrations.For(d)
		if errors.Is(err, migrations.ErrNotShipped) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if names, _ := fs.Glob(fsys, "*.sql"); len(names) == 0 {
			continue
		}
		if err := errors.Join(migrate.Validate(fsys, d, allowedMigrations()), checkGlobalTables(fsys, d)); err != nil {
			errs = append(errs, fmt.Errorf("%s:\n%w", d, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	_, err := fmt.Fprintln(fset.Output(), "migrations are valid")
	return err
}

// OpenDatabase opens the pools and refuses a schema that is behind this binary (D32). Hand Operator only
// to operator-realm wiring (D29); a build without the tenancy part refuses an operator URL. With the tenancy part it also installs the tenant transaction hooks,
// refuses pools whose roles could step around row-level security, and logs any table that breaks the
// schema rules; either way it refuses a database whose tenancy tables disagree with this build.
func OpenDatabase(ctx context.Context, cfg Config) (Deps, error) {
	if err := refuseOperator(cfg); err != nil {
		return Deps{}, err
	}
	d, operator, err := db.Open(ctx, cfg.Database, append(openOptions(cfg), otelOpenOptions(cfg)...)...)
	if err != nil {
		return Deps{}, err
	}
	fsys, err := migrations.For(d.Dialect())
	if err == nil {
		err = migrate.CheckCurrent(ctx, d, fsys)
	}
	deps := Deps{DB: d, Operator: operator}
	if err == nil {
		err = startTenancy(ctx, &deps)
	}
	if err != nil {
		_ = d.Close() // the schema error is the one to report
		return Deps{}, err
	}
	return deps, nil
}

// matchTenancySchema refuses a database whose tenancy tables disagree with the build: tables without
// the part, or the part without its tables.
func matchTenancySchema(ctx context.Context, d *db.DB, part bool) error {
	present := false
	if d.Dialect() == db.Postgres {
		err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			rows, err := tx.Q().QueryContext(ctx, "SELECT to_regclass('public.tenants') IS NOT NULL")
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				if err := rows.Scan(&present); err != nil {
					return err
				}
			}
			return rows.Err()
		}, db.ReadOnly())
		if err != nil {
			return fmt.Errorf("check the tenancy tables: %w", err)
		}
	}
	switch {
	case present && !part:
		return errors.New("the database has the tenancy tables but this build leaves the tenancy part out")
	case !present && part:
		return errors.New("this build has the tenancy part but the database has no tenancy tables; run migrate")
	}
	return nil
}
