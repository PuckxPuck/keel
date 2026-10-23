package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path"
	"slices"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

const (
	// Schema holds goose's version table on Postgres, owned by the owner role and closed to the app and
	// operator roles, which read the applied versions only through appliedFunc (a kit migration creates it).
	Schema       = "keel_migrations"
	versionTable = "goose_db_version"
	appliedFunc  = "public.keel_migrations_applied"
)

var (
	ErrDownRefused = errors.New("migrate down is refused in production and staging; fix forward")
	ErrBehind      = errors.New("database schema is behind this binary")
)

type Options struct {
	// Production refuses Down (staging and production).
	Production bool
	// Logger receives goose's progress lines; nil discards them.
	Logger *slog.Logger
}

// Migrator runs the migrations in fsys (one dialect's directory) against pool, which for Up and Down
// must connect as the owner role.
type Migrator struct {
	pool    *sql.DB
	dialect db.Dialect
	fsys    fs.FS
	opts    Options
}

func New(pool *sql.DB, dialect db.Dialect, fsys fs.FS, opts Options) *Migrator {
	return &Migrator{pool: pool, dialect: dialect, fsys: fsys, opts: opts}
}

type Result struct {
	Version  int64
	Name     string
	Duration time.Duration
}

type Status struct {
	Version   int64
	Name      string
	Applied   bool
	AppliedAt time.Time
}

func (m *Migrator) Up(ctx context.Context) ([]Result, error) {
	p, err := m.provider(ctx)
	if err != nil {
		return nil, err
	}
	results, err := p.Up(ctx)
	out := make([]Result, 0, len(results))
	for _, r := range results {
		out = append(out, result(r))
	}
	if err != nil {
		return out, fmt.Errorf("migrate up: %w", err)
	}
	return out, nil
}

// Down rolls back the latest migration; local work only.
func (m *Migrator) Down(ctx context.Context) (Result, error) {
	if m.opts.Production {
		return Result{}, ErrDownRefused
	}
	p, err := m.provider(ctx)
	if err != nil {
		return Result{}, err
	}
	r, err := p.Down(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("migrate down: %w", err)
	}
	return result(r), nil
}

func (m *Migrator) Status(ctx context.Context) ([]Status, error) {
	p, err := m.provider(ctx)
	if err != nil {
		return nil, err
	}
	statuses, err := p.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate status: %w", err)
	}
	out := make([]Status, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, Status{
			Version:   s.Source.Version,
			Name:      baseName(s.Source.Path),
			Applied:   s.State == goose.StateApplied,
			AppliedAt: s.AppliedAt,
		})
	}
	return out, nil
}

func (m *Migrator) Version(ctx context.Context) (int64, error) {
	p, err := m.provider(ctx)
	if err != nil {
		return 0, err
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate version: %w", err)
	}
	return v, nil
}

// Current is the startup schema check (D32). A database behind the binary is an error. A database ahead
// of it only logs a warning: during a deploy or rollback an older binary runs against expand-only newer
// schema. It reads through the app pool, so it needs no owner credentials.
func (m *Migrator) Current(ctx context.Context) error {
	files, err := fileVersions(m.fsys)
	if err != nil {
		return err
	}
	applied, err := m.applied(ctx)
	if err != nil {
		return err
	}
	var pending []int64
	for v := range files {
		if !applied[v] {
			pending = append(pending, v)
		}
	}
	if len(pending) > 0 {
		slices.Sort(pending)
		return fmt.Errorf("%w: %d pending, first %s; run migrate", ErrBehind, len(pending), files[pending[0]])
	}
	var unknown []int64
	for v := range applied {
		if _, ok := files[v]; !ok {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		logx.From(ctx).WarnContext(ctx, "database schema is ahead of this binary",
			"unknown_migrations", len(unknown), "latest", unknown[len(unknown)-1])
	}
	return nil
}

// CheckCurrent is Current on the app pool of d, for serve's startup check.
func CheckCurrent(ctx context.Context, d *db.DB, fsys fs.FS) error {
	return New(d.SQL(), d.Dialect(), fsys, Options{}).Current(ctx)
}

func (m *Migrator) applied(ctx context.Context) (map[int64]bool, error) {
	query := "SELECT version_id FROM " + versionTable + " WHERE version_id > 0"
	if m.dialect == db.Postgres {
		query = "SELECT v FROM " + appliedFunc + "() AS v"
	}
	rows, err := m.pool.QueryContext(ctx, query)
	if err != nil {
		if neverMigrated(err) {
			return map[int64]bool{}, nil
		}
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("read applied migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	return applied, nil
}

func (m *Migrator) provider(ctx context.Context) (*goose.Provider, error) {
	table := versionTable
	var locker lock.SessionLocker
	var err error
	switch m.dialect {
	case db.Postgres:
		if _, err := m.pool.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+Schema); err != nil {
			return nil, fmt.Errorf("create schema %s: %w", Schema, err)
		}
		table = Schema + "." + versionTable
		locker, err = lock.NewPostgresSessionLocker()
	case db.MySQL:
		locker = mysqlLocker{}
	}
	if err != nil {
		return nil, fmt.Errorf("migration locker: %w", err)
	}
	logOpt := goose.WithLogger(goose.NopLogger())
	if m.opts.Logger != nil {
		logOpt = goose.WithSlog(m.opts.Logger)
	}
	p, err := goose.NewProvider(goose.Dialect(m.dialect), m.pool, m.fsys,
		goose.WithTableName(table),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
		logOpt,
	)
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	return p, nil
}

func result(r *goose.MigrationResult) Result {
	return Result{Version: r.Source.Version, Name: baseName(r.Source.Path), Duration: r.Duration}
}

// fileVersions maps each migration version in fsys to its file name.
func fileVersions(fsys fs.FS) (map[int64]string, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	out := make(map[int64]string, len(names))
	for _, name := range names {
		f, err := parseName(name)
		if err != nil {
			return nil, err
		}
		out[f.version] = name
	}
	return out, nil
}

// Versions lists the migration versions in fsys, oldest first.
func Versions(fsys fs.FS) ([]int64, error) {
	files, err := fileVersions(fsys)
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(files)), nil
}

// Without hides the migrations of the named modules (the <module> in <timestamp>_<module>_<what>.sql),
// for databases that leave an optional part out, such as test templates without tenancy.
func Without(fsys fs.FS, modules ...string) fs.FS { return without{fsys: fsys, modules: modules} }

type without struct {
	fsys    fs.FS
	modules []string
}

func (w without) hidden(name string) bool {
	f, err := parseName(path.Base(name))
	return err == nil && slices.Contains(w.modules, f.module)
}

func (w without) Open(name string) (fs.File, error) {
	if w.hidden(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return w.fsys.Open(name)
}

func (w without) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(w.fsys, name)
	return slices.DeleteFunc(entries, func(e fs.DirEntry) bool { return w.hidden(path.Join(name, e.Name())) }), err
}
