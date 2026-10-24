// Package testdb gives each test package its own database, cloned from a template migrated once per run.
//
// APP_TEST_DATABASE_URL is a Postgres URL for a role that may create databases and roles; tests log in as
// a login role of the run that is a member of <prefix>_app, never the owner, and with no role switch.
// APP_TEST_MYSQL_URL is a MySQL URL for a user that may create databases. `keel test` sets both for the
// compose defaults when they are reachable.
package testdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

const (
	PostgresURLVar = "APP_TEST_DATABASE_URL"
	MySQLURLVar    = "APP_TEST_MYSQL_URL"

	setupTimeout = 2 * time.Minute
	maxAge       = 24 * time.Hour
	stampLayout  = "20060102150405"
	// templateVersion is part of every template's identity; bump it when how testdb builds templates changes.
	templateVersion = 2
)

type Options struct {
	// Migrations holds one directory per dialect, named after it ("postgres", "mysql").
	Migrations fs.FS
	// RolePrefix names the Postgres roles: <prefix>_owner runs migrations, tests connect as <prefix>_app.
	RolePrefix string
	// Template seeds the template after migrating; nil for an empty schema.
	Template *Template
}

type Template struct {
	name    string
	version int
	prepare func(ctx context.Context, owner *db.DB) error
}

// WithTemplate seeds the package template with prepare, run once per run as the owner. Bump version
// when prepare changes; the migrations are already part of the template's identity.
func WithTemplate(name string, version int, prepare func(ctx context.Context, owner *db.DB) error) *Template {
	return &Template{name: name, version: version, prepare: prepare}
}

// Engine is one database server under test.
type Engine struct {
	srv      server
	template string
	pkg      *db.DB
	pkgName  string
	// all is every migration of the dialect; package databases leave the tenancy part out.
	all fs.FS
	// names are the databases Isolated made, by pool, for Owner.
	names   sync.Map
	tenancy struct {
		once     sync.Once
		template string
		err      error
	}
}

func (e *Engine) Dialect() db.Dialect { return e.srv.dialect() }

// DB is the package database, shared by the package's tests; isolate by unique data.
func (e *Engine) DB() *db.DB { return e.pkg }

// Isolated returns a fresh database cloned from the template, dropped when t ends.
func (e *Engine) Isolated(t testing.TB) *db.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), setupTimeout)
	defer cancel()
	d, name, err := e.clone(ctx)
	if err != nil {
		t.Fatalf("testdb: isolated database: %v", err)
	}
	e.names.Store(d, name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		e.names.Delete(d)
		_ = d.Close() // a close error leaves only a connection to the dropped database
		if err := e.srv.drop(ctx, name); err != nil {
			t.Errorf("testdb: drop %s: %v", name, err)
		}
	})
	return d
}

// Owner connects to d's database (the package database, or one from Isolated) as the role that runs
// migrations: the owner on Postgres, the admin on MySQL. It is for tests that act beyond the app's
// grants, such as tampering with what the app may only append to; it closes when t ends.
func (e *Engine) Owner(t testing.TB, d *db.DB) *db.DB {
	t.Helper()
	name := e.pkgName
	if d != e.pkg {
		n, ok := e.names.Load(d)
		if !ok {
			t.Fatalf("testdb: the database is not this engine's package database or one from Isolated")
		}
		name = n.(string)
	}
	owner, err := e.srv.owner(t.Context(), name)
	if err != nil {
		t.Fatalf("testdb: connect as the owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}

// Empty returns a new database without any schema, connected as the role that runs migrations (the owner
// on Postgres), dropped when t ends; for tests that migrate themselves.
func (e *Engine) Empty(t testing.TB) *db.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), setupTimeout)
	defer cancel()
	name := testName(e.srv.prefix(), clock.Wall(ctx).Now())
	d, err := e.srv.empty(ctx, name)
	if err != nil {
		t.Fatalf("testdb: empty database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		_ = d.Close() // a close error leaves only a connection to the dropped database
		if err := e.srv.drop(ctx, name); err != nil {
			t.Errorf("testdb: drop %s: %v", name, err)
		}
	})
	return d
}

func (e *Engine) clone(ctx context.Context) (*db.DB, string, error) {
	name := testName(e.srv.prefix(), clock.Wall(ctx).Now())
	if err := e.srv.clone(ctx, e.template, name); err != nil {
		return nil, "", err
	}
	d, err := e.srv.connect(ctx, name)
	if err != nil {
		_ = e.srv.drop(ctx, name) // the connect error is the one to report
		return nil, "", err
	}
	return d, name, nil
}

var engines []*Engine

// Main sets up a package database on every configured engine, runs the tests and drops the databases.
func Main(m *testing.M, opts Options) {
	os.Exit(run(m, opts))
}

func run(m *testing.M, opts Options) int {
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	for _, s := range configured(opts) {
		e, err := setup(ctx, s, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "testdb: %s: %v\n", s.dialect(), err)
			teardown()
			return 1
		}
		engines = append(engines, e)
	}
	code := m.Run()
	teardown()
	return code
}

func configured(opts Options) []server {
	var out []server
	if u := os.Getenv(PostgresURLVar); u != "" { //nolint:forbidigo // test-only: the server comes from the environment
		out = append(out, &pgServer{adminURL: u, roles: newRoles(opts.RolePrefix)})
	}
	if u := os.Getenv(MySQLURLVar); u != "" { //nolint:forbidigo // test-only: the server comes from the environment
		out = append(out, &myServer{adminURL: u, pfx: newRoles(opts.RolePrefix).prefix})
	}
	return out
}

func setup(ctx context.Context, s server, opts Options) (*Engine, error) {
	if !validPrefix.MatchString(opts.RolePrefix) {
		return nil, fmt.Errorf("role prefix %q must be lower-case letters, digits and underscores", opts.RolePrefix)
	}
	if err := s.open(ctx); err != nil {
		return nil, err
	}
	all, err := fs.Sub(opts.Migrations, s.dialect().String())
	if err != nil {
		return nil, err
	}
	tenantModules, err := migrate.TenantModules(all, s.dialect())
	if err != nil {
		return nil, err
	}
	migrations := migrate.Without(all, append(tenantModules, TenancyModule)...)
	hash, err := templateHash(s.dialect(), migrations, opts.Template)
	if err != nil {
		return nil, err
	}
	tpl, err := s.ensureTemplate(ctx, hash, migrations, opts.Template)
	if err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	e := &Engine{srv: s, template: tpl, all: all}
	if e.pkg, e.pkgName, err = e.clone(ctx); err != nil {
		return nil, fmt.Errorf("package database: %w", err)
	}
	return e, nil
}

func teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	for _, e := range engines {
		if e.pkg != nil {
			_ = e.pkg.Close() // the database is dropped next
			if err := e.srv.drop(ctx, e.pkgName); err != nil {
				fmt.Fprintf(os.Stderr, "testdb: drop %s: %v\n", e.pkgName, err)
			}
		}
		e.srv.close()
	}
	engines = nil
}

// TenancyModule names the tenancy part's migrations (<timestamp>_tenancy_<what>.sql). Package databases
// leave them out, so kit tests run as an app without tenancy on both engines, and with them every module
// whose tables are tenant tables from their first migration (D36); Tenancy has those.
const TenancyModule = "tenancy"

// TenancyDB is a fresh Postgres database with every migration, the tenancy part included.
type TenancyDB struct {
	// DB logs in as a member of the app role; Operator opens transactions as a member of
	// <prefix>_operator that bypasses row-level security.
	DB       *db.DB
	Operator *db.OperatorAccess
	srv      *pgServer
	name     string
	// passwords holds the password of each role TempRole made.
	passwords sync.Map
}

// As connects to the database as a new login role that is a member of another test role ("owner", "app"
// or "operator", with the operator's bypassrls), for checks of what a misconfigured pool could do; the
// connection closes when t ends.
func (d *TenancyDB) As(t testing.TB, role string) *db.DB {
	t.Helper()
	r := d.srv.roles
	attrs := map[string]string{
		"owner": "NOBYPASSRLS IN ROLE " + quote(r.owner), "app": "NOBYPASSRLS IN ROLE " + quote(r.app), "operator": "BYPASSRLS IN ROLE " + quote(r.operator),
	}
	a, ok := attrs[role]
	if !ok {
		t.Fatalf("testdb: unknown role %q", role)
	}
	return d.AsRole(t, d.TempRole(t, a))
}

// AsRole logs in to the database as a role made with TempRole, through db.Open as an app does.
func (d *TenancyDB) AsRole(t testing.TB, role string) *db.DB {
	t.Helper()
	password, ok := d.passwords.Load(role)
	if !ok {
		t.Fatalf("testdb: %s is not a role made with TempRole", role)
	}
	u, err := d.srv.urlFor(d.name, role, password.(string))
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	cfg := newConfig()
	cfg.URL = config.Secret(u)
	pool, _, err := db.Open(t.Context(), cfg, db.ResetTenant())
	if err != nil {
		t.Fatalf("testdb: connect as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// AsOperator opens the app pool and an operator pool logged in as role, made with TempRole, through
// db.Open; for checks of what an operator role may hold. The pools close when t ends.
func (d *TenancyDB) AsOperator(t testing.TB, role string) *db.OperatorAccess {
	t.Helper()
	password, ok := d.passwords.Load(role)
	if !ok {
		t.Fatalf("testdb: %s is not a role made with TempRole", role)
	}
	appURL, err := d.srv.urlFor(d.name, d.srv.logins.app, d.srv.logins.password)
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	operatorURL, err := d.srv.urlFor(d.name, role, password.(string))
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	cfg := newConfig()
	cfg.URL, cfg.OperatorURL = config.Secret(appURL), config.Secret(operatorURL)
	pool, operator, err := db.Open(t.Context(), cfg, db.ResetTenant())
	if err != nil {
		t.Fatalf("testdb: connect the operator pool as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return operator
}

// AdminURL is the database's URL as the server's admin, a superuser, for commands that migrate it.
func (d *TenancyDB) AdminURL(t testing.TB) string {
	t.Helper()
	u, err := d.srv.urlFor(d.name, "", "")
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	return u
}

// Admin runs statements on the database as the server's admin, a superuser; {db} in a statement is
// the database's name.
func (d *TenancyDB) Admin(t testing.TB, stmts ...string) {
	t.Helper()
	u, err := d.srv.urlFor(d.name, "", "")
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	pool, _, err := db.OpenSQL(t.Context(), u, newConfig())
	if err != nil {
		t.Fatalf("testdb: connect as admin: %v", err)
	}
	defer func() { _ = pool.Close() }()
	for _, stmt := range stmts {
		if _, err := pool.ExecContext(t.Context(), strings.ReplaceAll(stmt, "{db}", quote(d.name))); err != nil {
			t.Fatalf("testdb: %s: %v", stmt, err)
		}
	}
}

// TempRole makes a login role with the given attributes (such as "bypassrls") for one test and drops it,
// and whatever it owns here, when the test ends; roles are shared by every database on the server.
func (d *TenancyDB) TempRole(t testing.TB, attrs string) string {
	t.Helper()
	name, password := d.srv.roles.prefix+"_t_"+randomHex(6), randomHex(16)
	d.Admin(t, "CREATE ROLE "+quote(name)+" LOGIN PASSWORD '"+password+"' "+attrs)
	d.passwords.Store(name, password)
	t.Cleanup(func() {
		u, err := d.srv.urlFor(d.name, "", "")
		if err != nil {
			return
		}
		pool, _, err := db.OpenSQL(context.Background(), u, newConfig())
		if err != nil {
			t.Errorf("testdb: drop role %s: %v", name, err)
			return
		}
		defer func() { _ = pool.Close() }()
		for _, stmt := range []string{"DROP OWNED BY " + quote(name), "DROP ROLE " + quote(name)} {
			if _, err := pool.ExecContext(context.Background(), stmt); err != nil {
				t.Errorf("testdb: %s: %v", stmt, err)
			}
		}
	})
	return name
}

// NewTenant adds an active tenant with slug (and the same name) through the operator pool and returns
// its id, for tests that need tenants without the tenancy service.
func (d *TenancyDB) NewTenant(t testing.TB, slug string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	err := db.InOperatorTx(t.Context(), d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		_, err := tx.Q().ExecContext(ctx, "INSERT INTO tenants (id, slug, name, created_at, updated_at) VALUES ($1, $2, $2, now(), now())", id, slug)
		return err
	})
	if err != nil {
		t.Fatalf("testdb: tenant %s: %v", slug, err)
	}
	return id
}

// Tenancy returns a fresh tenancy database (Postgres only), dropped when t ends; it skips the test
// without a Postgres engine.
func Tenancy(t testing.TB) *TenancyDB {
	t.Helper()
	for _, e := range engines {
		if pg, ok := e.srv.(*pgServer); ok {
			return e.tenancyDatabase(t, pg)
		}
	}
	t.Skipf("tenancy needs Postgres: set %s (keel test does this)", PostgresURLVar)
	return nil
}

func (e *Engine) tenancyDatabase(t testing.TB, pg *pgServer) *TenancyDB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), setupTimeout)
	defer cancel()
	e.tenancy.once.Do(func() {
		var hash string
		if hash, e.tenancy.err = templateHash(db.Postgres, e.all, nil); e.tenancy.err == nil {
			e.tenancy.template, e.tenancy.err = pg.ensureTemplate(ctx, hash, e.all, nil)
		}
	})
	if e.tenancy.err != nil {
		t.Fatalf("testdb: tenancy template: %v", e.tenancy.err)
	}
	name := testName(pg.prefix(), clock.Wall(ctx).Now())
	if err := pg.clone(ctx, e.tenancy.template, name); err != nil {
		t.Fatalf("testdb: tenancy database: %v", err)
	}
	d, operator, err := pg.connectWithOperator(ctx, name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		if d != nil {
			_ = d.Close() // a close error leaves only a connection to the dropped database
		}
		if err := pg.drop(ctx, name); err != nil {
			t.Errorf("testdb: drop %s: %v", name, err)
		}
	})
	if err != nil {
		t.Fatalf("testdb: connect to %s: %v", name, err)
	}
	return &TenancyDB{DB: d, Operator: operator, srv: pg, name: name}
}

// Each runs fn as a subtest on every configured engine, so one contract test covers both dialects.
func Each(t *testing.T, fn func(t *testing.T, e *Engine)) {
	t.Helper()
	if len(engines) == 0 {
		t.Skipf("no test database: set %s or %s (keel test does this)", PostgresURLVar, MySQLURLVar)
	}
	for _, e := range engines {
		t.Run(e.Dialect().String(), func(t *testing.T) { fn(t, e) })
	}
}

// Get returns the package database of the first configured engine (Postgres when both are set).
func Get(t testing.TB) *db.DB {
	t.Helper()
	return primary(t).DB()
}

// Isolated returns a fresh database on the first configured engine.
func Isolated(t testing.TB) *db.DB {
	t.Helper()
	return primary(t).Isolated(t)
}

func primary(t testing.TB) *Engine {
	t.Helper()
	if len(engines) == 0 {
		t.Skipf("no test database: set %s or %s (keel test does this)", PostgresURLVar, MySQLURLVar)
	}
	return engines[0]
}

func templateHash(dialect db.Dialect, migrations fs.FS, tpl *Template) (string, error) {
	names, err := fs.Glob(migrations, "*.sql")
	if err != nil {
		return "", err
	}
	slices.Sort(names)
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "testdb %d %s\n", templateVersion, dialect) // hash writes never fail
	for _, name := range names {
		raw, err := fs.ReadFile(migrations, name)
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(h, "%s %d\n", name, len(raw))
		_, _ = h.Write(raw)
	}
	if tpl != nil {
		_, _ = fmt.Fprintf(h, "template %s %d\n", tpl.name, tpl.version)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

var validPrefix = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)

type roles struct{ prefix, owner, app, operator string }

func newRoles(prefix string) roles {
	return roles{prefix: prefix, owner: prefix + "_owner", app: prefix + "_app", operator: prefix + "_operator"}
}

// Every database testdb makes is named <prefix>_testdb_<UTC stamp>_<8 hex> (package, isolated and empty
// databases) or <prefix>_testdb_tpl_<12 hex hash>_<UTC stamp> (templates). The janitor drops only names
// that parse back into one of these shapes.
const marker = "_testdb_"

func testName(prefix string, now time.Time) string {
	return prefix + marker + now.UTC().Format(stampLayout) + "_" + randomHex(4)
}

func templateBase(prefix, hash string) string { return prefix + marker + "tpl_" + hash + "_" }

func templateName(prefix, hash string, now time.Time) string {
	return templateBase(prefix, hash) + now.UTC().Format(stampLayout)
}

type generated struct {
	template bool
	hash     string
	at       time.Time
}

var (
	testShape     = regexp.MustCompile(`^(\d{14})_[0-9a-f]{8}$`)
	templateShape = regexp.MustCompile(`^tpl_([0-9a-f]{12})_(\d{14})$`)
)

// parseGenerated reports whether name is one testdb made for prefix, and what it is.
func parseGenerated(name, prefix string) (generated, bool) {
	rest, ok := strings.CutPrefix(name, prefix+marker)
	if !ok {
		return generated{}, false
	}
	var g generated
	stamp := ""
	if m := templateShape.FindStringSubmatch(rest); m != nil {
		g.template, g.hash, stamp = true, m[1], m[2]
	} else if m := testShape.FindStringSubmatch(rest); m != nil {
		stamp = m[1]
	} else {
		return generated{}, false
	}
	at, err := time.Parse(stampLayout, stamp)
	if err != nil {
		return generated{}, false
	}
	g.at = at
	return g, true
}

// reusable reports whether a ready template is young enough to hand out. Another package's janitor drops
// templates past maxAge whatever their hash, so one in use must stay well short of it.
func reusable(name, prefix string, now time.Time) bool {
	g, ok := parseGenerated(name, prefix)
	return ok && now.Sub(g.at) < maxAge/2
}

// expired reports whether the janitor may drop name: a database testdb made, older than maxAge, and not
// the current template.
func expired(name, prefix, currentHash string, now time.Time) bool {
	g, ok := parseGenerated(name, prefix)
	if !ok || (g.template && g.hash == currentHash) {
		return false
	}
	return now.Sub(g.at) > maxAge
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

func newConfig() db.Config {
	cfg := db.Defaults()
	cfg.MaxOpen, cfg.MaxIdle = 8, 4
	return cfg
}

type server interface {
	dialect() db.Dialect
	prefix() string
	open(ctx context.Context) error
	close()
	ensureTemplate(ctx context.Context, hash string, migrations fs.FS, tpl *Template) (string, error)
	clone(ctx context.Context, template, name string) error
	empty(ctx context.Context, name string) (*db.DB, error)
	connect(ctx context.Context, name string) (*db.DB, error)
	owner(ctx context.Context, name string) (*db.DB, error)
	drop(ctx context.Context, name string) error
}
