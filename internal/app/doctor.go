package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

type CheckStatus string

const (
	Pass CheckStatus = "pass"
	Warn CheckStatus = "warn"
	Fail CheckStatus = "fail"
	// Skip is a check that could not run because of another's failure, which that one reports.
	Skip CheckStatus = "skip"
)

// Check is one line of doctor's report.
type Check struct {
	Name   string
	Status CheckStatus
	Detail string
}

func pass(name, detail string) Check { return Check{Name: name, Status: Pass, Detail: detail} }
func warn(name, detail string) Check { return Check{Name: name, Status: Warn, Detail: detail} }
func fail(name, detail string) Check { return Check{Name: name, Status: Fail, Detail: detail} }
func skip(name, detail string) Check { return Check{Name: name, Status: Skip, Detail: detail} }

const (
	probeTimeout = 3 * time.Second
	// maxClockSkew is how far the host's clock may be from the database's: leases compare the two.
	maxClockSkew = 2 * time.Second
	// laneBacklog is how long a ready job may wait before its lane counts as backed up.
	laneBacklog = 10 * time.Minute
	// workerSilence is how long the hourly retention schedule may go unrun before no worker counts as seen.
	workerSilence = 2 * time.Hour
	// buildAge is when a build is old enough that its dependencies may carry known vulnerabilities.
	buildAge = 30 * 24 * time.Hour
)

func doctor(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		var checks []Check
		cfg, err := LoadConfig(environ)
		if err != nil {
			checks = append(checks, fail("configuration", strings.ReplaceAll(err.Error(), "\n", "; ")))
		} else {
			deps, err := openForDoctor(ctx, cfg)
			if err == nil {
				defer func() { _ = deps.DB.Close() }()
			}
			checks = Diagnose(ctx, cfg, deps)
			if err != nil {
				checks = slices.Insert(checks, 1, unreachable(cfg, err)...)
			}
		}
		table := cli.Table{Columns: []string{"check", "status", "detail"}}
		failed := 0
		for _, c := range checks {
			table.Rows = append(table.Rows, []string{c.Name, string(c.Status), c.Detail})
			if c.Status == Fail {
				failed++
			}
		}
		if err := cli.Print(fs.Output(), cli.WantsJSON(fs), table); err != nil {
			return err
		}
		if failed > 0 {
			return fmt.Errorf("doctor: %d of %d checks failed", failed, len(checks))
		}
		return nil
	}
}

// openForDoctor opens the pools without the schema and role gates serve has, so each of those is a check
// of its own; opening gives up after probeTimeout.
func openForDoctor(ctx context.Context, cfg Config) (Deps, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	d, operator, err := db.Open(ctx, cfg.Database, openOptions(cfg)...)
	if err != nil {
		return Deps{}, err
	}
	return Deps{DB: d, Operator: operator, Tenancy: tenancyPart(d.Dialect())}, nil
}

// unreachable is the database line when the pools would not open, and the database checks it leaves
// unrun.
func unreachable(cfg Config, err error) []Check {
	checks := []Check{fail("database", "unreachable: "+err.Error())}
	names := []string{"migrations", "jobs", "clock"}
	if d, derr := db.DialectOf(string(cfg.Database.URL)); derr == nil && tenancyPart(d) {
		names = []string{"migrations", "roles", "row-level security", "jobs", "clock"}
	}
	for _, name := range names {
		checks = append(checks, skip(name, "needs the database"))
	}
	return checks
}

// Diagnose runs every doctor check against a loaded configuration and, when deps.DB is set, the opened
// database. Each network or database check gives up after probeTimeout and reports under its own name;
// a failure in one leaves the others to run. Nothing is sent and probe objects are removed.
func Diagnose(ctx context.Context, cfg Config, deps Deps) []Check {
	checks := []Check{checkProfile(cfg)}
	if deps.DB != nil {
		checks = append(checks, bounded(ctx, func(ctx context.Context) Check { return checkDatabase(ctx, cfg, deps.DB) }))
		migrations, behind := checkMigrations(ctx, deps.DB)
		checks = append(checks, migrations)
		checks = append(checks, checkTenancy(ctx, deps, behind)...)
		jobsCheck := skip("jobs", "needs the current schema: migrations are behind")
		if !behind {
			jobsCheck = bounded(ctx, func(ctx context.Context) Check { return checkJobs(ctx, cfg, deps) })
		}
		checks = append(checks, jobsCheck, bounded(ctx, func(ctx context.Context) Check { return checkClock(ctx, deps.DB) }))
	}
	checks = append(checks, checkOperations(ctx, cfg))
	checks = append(checks, mailChecks(ctx, cfg)...)
	checks = append(checks, filesChecks(ctx, cfg)...)
	checks = append(checks, pdfChecks(ctx, cfg)...)
	checks = append(checks, checkKeys(cfg), checkBuild(ctx))
	return checks
}

// bounded runs one check under its own probeTimeout.
func bounded(ctx context.Context, check func(ctx context.Context) Check) Check {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return check(ctx)
}

func checkProfile(cfg Config) Check {
	if cfg.Env.IsProd() {
		return pass("configuration", "valid for "+string(cfg.Env)+" (production profile)")
	}
	return pass("configuration", "valid for "+string(cfg.Env))
}

func checkDatabase(ctx context.Context, cfg Config, d *db.DB) Check {
	start := clock.Wall(ctx).Now()
	err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		_, err := tx.Q().ExecContext(ctx, "SELECT 1")
		return err
	}, db.ReadOnly())
	took := clock.Wall(ctx).Now().Sub(start).Round(time.Millisecond)
	switch {
	case err != nil:
		return fail("database", "unreachable: "+err.Error())
	case !cfg.Database.VerifiesTLS():
		return warn("database", fmt.Sprintf("%s reachable in %s, TLS not verified", d.Dialect(), took))
	}
	return pass("database", fmt.Sprintf("%s reachable in %s, TLS verified", d.Dialect(), took))
}

// checkMigrations also reports whether the schema is behind, which leaves the checks that read it unrun.
func checkMigrations(ctx context.Context, d *db.DB) (Check, bool) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	fsys, err := migrations.For(d.Dialect())
	if err == nil {
		err = migrate.CheckCurrent(ctx, d, fsys)
	}
	if err != nil {
		return fail("migrations", err.Error()), errors.Is(err, migrate.ErrBehind)
	}
	return pass("migrations", "the database has every migration this binary ships"), false
}

// checkNoTenancy is the tenancy line of a build or database without the part; a database that has the
// tenancy tables anyway fails.
func checkNoTenancy(ctx context.Context, d *db.DB) []Check {
	checks := []Check{pass("roles", "no tenancy: no row-level security to step around")}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := matchTenancySchema(ctx, d, false); err != nil {
		checks = append(checks, fail("row-level security", err.Error()))
	}
	return checks
}

func checkOperations(ctx context.Context, cfg Config) Check {
	set, err := Operations()
	if err == nil {
		err = CheckOperations(ctx, set, newLimiter(cfg.Rate, nil))
	}
	if err != nil {
		return fail("operations", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	return pass("operations", "every operation has a Need and a defined rate-limit class")
}

// checkJobs looks at the queue: a worker seen within workerSilence (the hourly retention schedule ran),
// no lane waiting past laneBacklog, and no running job whose lease ran out unreaped.
func checkJobs(ctx context.Context, cfg Config, deps Deps) Check {
	if deps.Tenancy && deps.Operator == nil {
		return skip("jobs", "under tenancy the queue runs on the operator pool, which is not configured")
	}
	q, err := jobs.New(jobs.Options{Config: cfg.Jobs, Tx: queueTx(deps)})
	if err != nil {
		return fail("jobs", err.Error())
	}
	now := clock.Wall(ctx).Now()
	var problems []string
	schedules, err := q.Schedules(ctx)
	if err != nil {
		return fail("jobs", err.Error())
	}
	var last time.Time
	for _, s := range schedules {
		if s.LastRunAt != nil && s.LastRunAt.After(last) {
			last = *s.LastRunAt
		}
	}
	if now.Sub(last) > workerSilence {
		problems = append(problems, "no worker has run a schedule in the last "+workerSilence.String())
	}
	status, err := q.Status(ctx)
	if err != nil {
		return fail("jobs", err.Error())
	}
	for _, s := range status {
		if s.Status == jobs.Queued && now.Sub(s.OldestAt) > laneBacklog {
			problems = append(problems, fmt.Sprintf("lane %s has %s jobs waiting since %s", s.Lane, s.Kind, s.OldestAt.UTC().Format(time.RFC3339)))
		}
	}
	overdue, err := q.Overdue(ctx)
	if err != nil {
		return fail("jobs", err.Error())
	}
	if overdue > 0 {
		problems = append(problems, fmt.Sprintf("%d running jobs are past their lease and not reaped", overdue))
	}
	if len(problems) > 0 {
		return warn("jobs", strings.Join(problems, "; "))
	}
	return pass("jobs", "workers seen, no lane backed up, no job past its lease")
}

func checkClock(ctx context.Context, d *db.DB) Check {
	q := "SELECT EXTRACT(EPOCH FROM clock_timestamp())"
	if d.Dialect() == db.MySQL {
		q = "SELECT UNIX_TIMESTAMP(NOW(6))"
	}
	var raw string
	err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		rows, err := tx.Q().QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if rows.Next() {
			err = rows.Scan(&raw)
		}
		return errors.Join(err, rows.Err())
	}, db.ReadOnly())
	secs, perr := strconv.ParseFloat(raw, 64)
	if err != nil || perr != nil {
		return fail("clock", "cannot read the database's time")
	}
	skew := time.Duration((secs - float64(clock.Wall(ctx).Now().UnixNano())/1e9) * float64(time.Second)).Abs()
	if skew > maxClockSkew {
		return fail("clock", fmt.Sprintf("this host is %s from the database (at most %s)", skew.Round(time.Millisecond), maxClockSkew))
	}
	return pass("clock", "within "+maxClockSkew.String()+" of the database")
}

// keySet is one set of keys doctor reports on.
type keySet struct {
	name string
	keys []config.Secret
}

// checkKeys reports which key sets are present; configuration has already refused short ones in the
// production profile, so here a short or example key outside it is a warning.
func checkKeys(cfg Config) Check {
	if len(cfg.Session.Keys) == 0 {
		return warn("keys", "no APP_SESSION_KEYS: signed values use a random key per process")
	}
	sets := append(append([]keySet{{name: "MFA", keys: cfg.MFA.Keys}}, connectionKeySets(cfg)...), webhookKeySets(cfg)...)
	var weak []string
	counts := []string{fmt.Sprintf("session %d", len(cfg.Session.Keys))}
	for _, set := range sets {
		counts = append(counts, fmt.Sprintf("%s %d", set.name, len(set.keys)))
		for _, k := range set.keys {
			if config.RequireStrong(set.name, k, true) != nil {
				weak = append(weak, set.name)
				break
			}
		}
	}
	slices.Sort(weak)
	mfa := false
	for _, r := range configuredRealms(cfg) {
		mfa = mfa || r.MFA != realm.MFAOff
	}
	switch {
	case mfa && len(cfg.MFA.Keys) == 0:
		return fail("keys", "a realm uses MFA without APP_MFA_KEYS")
	case len(weak) > 0:
		return warn("keys", "shorter than 32 bytes or an example value: "+strings.Join(weak, ", "))
	}
	return pass("keys", strings.Join(counts, ", "))
}

func checkBuild(ctx context.Context) Check {
	info := buildinfo.Get()
	detail := info.Version
	if info.Commit != "" {
		detail += " " + info.Commit
	}
	built, err := time.Parse(time.RFC3339, info.BuildTime)
	if err != nil {
		return warn("build", detail+", build time unknown, so its dependencies' age is too")
	}
	if age := clock.Wall(ctx).Now().Sub(built); age > buildAge {
		return warn("build", fmt.Sprintf("%s, built %d days ago: rebuild to take in dependency security fixes (govulncheck)", detail, int(age.Hours()/24)))
	}
	return pass("build", detail+", built "+built.UTC().Format(time.DateOnly))
}
