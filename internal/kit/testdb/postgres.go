package testdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

type pgServer struct {
	adminURL string
	roles    roles
	admin    *sql.DB
	// logins are this run's login roles, members of the shared roles; tests log in as them directly, as
	// apps do, so no startup parameter switches the role (db.Open refuses one).
	logins logins
}

type logins struct{ app, operator, owner, password string }

func (s *pgServer) dialect() db.Dialect { return db.Postgres }
func (s *pgServer) prefix() string      { return s.roles.prefix }

func (s *pgServer) open(ctx context.Context) error {
	admin, _, err := db.OpenSQL(ctx, s.adminURL, newConfig())
	if err != nil {
		return err
	}
	s.admin = admin
	return nil
}

func (s *pgServer) close() {
	if s.admin == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	for _, role := range []string{s.logins.app, s.logins.operator, s.logins.owner} {
		if role == "" {
			continue
		}
		if _, err := s.admin.ExecContext(ctx, "DROP ROLE IF EXISTS "+quote(role)); err != nil {
			fmt.Fprintf(os.Stderr, "testdb: drop role %s: %v\n", role, err)
		}
	}
	_ = s.admin.Close() // nothing left to do with the error at teardown
}

// urlFor points the admin URL at database name, logging in as user when one is given.
func (s *pgServer) urlFor(name, user, password string) (string, error) {
	u, err := url.Parse(s.adminURL)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid URL", PostgresURLVar)
	}
	u.Path = "/" + name
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	return u.String(), nil
}

// loginShape is a run's login role: <prefix>_tl_<UTC stamp>_<8 hex>_<role>.
var loginShape = regexp.MustCompile(`^_tl_(\d{14})_[0-9a-f]{8}_(?:app|operator|owner)$`)

// ensureLogins makes this run's login roles, once the shared roles exist.
func (s *pgServer) ensureLogins(ctx context.Context, conn *sql.Conn) error {
	if s.logins.app != "" {
		return nil
	}
	base := s.roles.prefix + "_tl_" + clock.Wall(ctx).Now().UTC().Format(stampLayout) + "_" + randomHex(4)
	l := logins{app: base + "_app", operator: base + "_operator", owner: base + "_owner", password: randomHex(16)}
	for _, role := range []struct{ name, attrs, member string }{
		{l.app, "NOBYPASSRLS", s.roles.app}, {l.operator, "BYPASSRLS", s.roles.operator}, {l.owner, "NOBYPASSRLS", s.roles.owner},
	} {
		stmt := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION %s IN ROLE %s",
			quote(role.name), l.password, role.attrs, quote(role.member))
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("login role %s: %w", role.name, err)
		}
	}
	s.logins = l
	return nil
}

// dropStaleLogins drops login roles a run more than a day old left behind (best effort).
func (s *pgServer) dropStaleLogins(ctx context.Context, conn *sql.Conn, now time.Time) {
	found, err := loginRoles(ctx, conn, s.roles.prefix+"_tl_")
	if err != nil {
		return
	}
	for _, name := range found {
		m := loginShape.FindStringSubmatch(strings.TrimPrefix(name, s.roles.prefix))
		if m == nil {
			continue
		}
		if at, err := time.Parse(stampLayout, m[1]); err == nil && now.Sub(at) > maxAge {
			_, _ = conn.ExecContext(ctx, "DROP ROLE IF EXISTS "+quote(name)) // best effort
		}
	}
}

func loginRoles(ctx context.Context, conn *sql.Conn, prefix string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT rolname FROM pg_roles WHERE starts_with(rolname, $1)", prefix)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// setRole is the owner pool's connector: the run's owner login takes on the shared owner role, so the
// objects migrations make belong to it and templates outlive the run. Only migrations use this pool;
// db.Open and the role checks never see it.
type setRole struct {
	driver.Connector
	role string
}

func (c setRole) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	exec, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("testdb: the driver cannot execute statements")
	}
	if _, err := exec.ExecContext(ctx, "SET ROLE "+quote(c.role), nil); err != nil {
		_ = conn.Close() // the SET ROLE error is the one to report
		return nil, err
	}
	return conn, nil
}

func (s *pgServer) ensureTemplate(ctx context.Context, hash string, migrations fs.FS, tpl *Template) (string, error) {
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	key := s.roles.prefix + ":testdb"
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(hashtext($1))", key); err != nil {
		return "", fmt.Errorf("lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext($1))", key)
	}()

	s.janitor(ctx, conn, hash)
	s.dropStaleLogins(ctx, conn, clock.Wall(ctx).Now())
	if err := s.ensureRoles(ctx, conn); err != nil {
		return "", err
	}
	if err := s.ensureLogins(ctx, conn); err != nil {
		return "", err
	}
	base := templateBase(s.roles.prefix, hash)
	var existing string
	err = conn.QueryRowContext(ctx,
		"SELECT datname FROM pg_database WHERE starts_with(datname, $1) AND datistemplate ORDER BY datname DESC LIMIT 1", base).Scan(&existing)
	switch {
	case err == nil && reusable(existing, s.roles.prefix, clock.Wall(ctx).Now()):
		return existing, nil
	case err == nil:
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	if err := s.dropUnfinished(ctx, conn, hash); err != nil {
		return "", err
	}
	name := templateName(s.roles.prefix, hash, clock.Wall(ctx).Now())
	if err := s.build(ctx, conn, name, migrations, tpl); err != nil {
		return "", err
	}
	return name, nil
}

func (s *pgServer) build(ctx context.Context, conn *sql.Conn, name string, migrations fs.FS, tpl *Template) error {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s OWNER %s", quote(name), quote(s.roles.owner))); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	owner, err := s.openAsOwner(ctx, name)
	if err != nil {
		return err
	}
	defer func() { _ = owner.Close() }()
	if _, err := migrate.New(owner.SQL(), db.Postgres, migrations, migrate.Options{}).Up(ctx); err != nil {
		return err
	}
	if tpl != nil {
		if err := tpl.prepare(ctx, owner); err != nil {
			return fmt.Errorf("prepare %s: %w", tpl.name, err)
		}
	}
	if err := owner.Close(); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, fmt.Sprintf("ALTER DATABASE %s WITH ALLOW_CONNECTIONS false IS_TEMPLATE true", quote(name)))
	return err
}

// grant mirrors deploy/db/postgres-roles.sql inside the template, which clones inherit.
func (s *pgServer) grant(ctx context.Context, name string) error {
	adminURL, err := s.urlFor(name, "", "")
	if err != nil {
		return err
	}
	conn, _, err := db.OpenSQL(ctx, adminURL, newConfig())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	r := s.roles
	for _, stmt := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s, %s", quote(r.app), quote(r.operator)),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s, %s",
			quote(r.owner), quote(r.app), quote(r.operator)),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s, %s",
			quote(r.owner), quote(r.app), quote(r.operator)),
	} {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("grant: %w", err)
		}
	}
	return nil
}

// ensureRoles creates the roles where the server lacks them (CI; locally deploy/db/local-init.sh made them)
// and on every run resets attributes that would let a role escape row-level security, as the roles script does.
func (s *pgServer) ensureRoles(ctx context.Context, conn *sql.Conn) error {
	r := s.roles
	for _, role := range []struct {
		name   string
		bypass bool
	}{{r.owner, false}, {r.app, false}, {r.operator, true}} {
		attrs := "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
		if role.bypass {
			attrs = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS"
		}
		var exists, wrong bool
		err := conn.QueryRowContext(ctx, `SELECT COUNT(*) > 0, COALESCE(bool_or(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
			OR rolbypassrls <> $2), false) FROM pg_roles WHERE rolname = $1`, role.name, role.bypass).Scan(&exists, &wrong)
		if err != nil {
			return err
		}
		stmt := ""
		switch {
		case !exists:
			stmt = fmt.Sprintf("CREATE ROLE %s NOLOGIN %s", quote(role.name), attrs)
		case wrong:
			stmt = fmt.Sprintf("ALTER ROLE %s %s", quote(role.name), attrs)
		default:
			continue
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("role %s: %w", role.name, err)
		}
	}
	return revokeMemberships(ctx, conn, r.app)
}

// revokeMemberships takes role out of every role it belongs to: the app role belongs to none, and a
// membership would carry it around row-level security without changing its own attributes.
func revokeMemberships(ctx context.Context, conn *sql.Conn, role string) error {
	rows, err := conn.QueryContext(ctx, `SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
		JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = $1`, role)
	if err != nil {
		return err
	}
	granted, err := collect(rows)
	if err != nil {
		return err
	}
	for _, g := range granted {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("REVOKE %s FROM %s", quote(g), quote(role))); err != nil {
			return fmt.Errorf("revoke %s from %s: %w", g, role, err)
		}
	}
	return nil
}

func (s *pgServer) clone(ctx context.Context, template, name string) error {
	_, err := s.admin.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s OWNER %s", quote(name), quote(template), quote(s.roles.owner)))
	return err
}

func (s *pgServer) connect(ctx context.Context, name string) (*db.DB, error) {
	appURL, err := s.urlFor(name, s.logins.app, s.logins.password)
	if err != nil {
		return nil, err
	}
	cfg := newConfig()
	cfg.URL = config.Secret(appURL)
	d, _, err := db.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := s.refuseEscapingRole(ctx, d.SQL()); err != nil {
		_ = d.Close() // the role error is the one to report
		return nil, err
	}
	return d, nil
}

// connectWithOperator opens the app pool and an operator pool, logged in as members of <prefix>_app and
// <prefix>_operator, through db.Open, the one maker of the operator capability.
func (s *pgServer) connectWithOperator(ctx context.Context, name string) (*db.DB, *db.OperatorAccess, error) {
	appURL, err := s.urlFor(name, s.logins.app, s.logins.password)
	if err != nil {
		return nil, nil, err
	}
	operatorURL, err := s.urlFor(name, s.logins.operator, s.logins.password)
	if err != nil {
		return nil, nil, err
	}
	cfg := newConfig()
	cfg.URL, cfg.OperatorURL = config.Secret(appURL), config.Secret(operatorURL)
	d, operator, err := db.Open(ctx, cfg, db.ResetTenant())
	if err != nil {
		return nil, nil, err
	}
	if err := s.refuseEscapingRole(ctx, d.SQL()); err != nil {
		_ = d.Close() // the role error is the one to report
		return nil, nil, err
	}
	return d, operator, nil
}

// refuseEscapingRole stops a test run whose app role would not be held by row-level security: it is, or
// belongs (through any chain of memberships) to, a superuser, a role that bypasses it, or the owner or
// operator role.
func (s *pgServer) refuseEscapingRole(ctx context.Context, pool *sql.DB) error {
	rows, err := pool.QueryContext(ctx, `SELECT rolname FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER')
		AND (r.rolsuper OR r.rolbypassrls OR r.rolname IN ($1, $2)) ORDER BY 1`, s.roles.owner, s.roles.operator)
	if err != nil {
		return fmt.Errorf("check the app role: %w", err)
	}
	escapes, err := collect(rows)
	if err != nil {
		return fmt.Errorf("check the app role: %w", err)
	}
	if len(escapes) > 0 {
		return fmt.Errorf("the app role is or belongs to %s, a superuser, a role that bypasses row-level security, or the owner or operator role; tests must run under it",
			strings.Join(escapes, ", "))
	}
	return nil
}

func (s *pgServer) empty(ctx context.Context, name string) (*db.DB, error) {
	if _, err := s.admin.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s OWNER %s", quote(name), quote(s.roles.owner))); err != nil {
		return nil, err
	}
	d, err := s.openAsOwner(ctx, name)
	if err != nil {
		_ = s.drop(ctx, name) // the open error is the one to report
		return nil, err
	}
	return d, nil
}

func (s *pgServer) owner(ctx context.Context, name string) (*db.DB, error) {
	return s.openAsOwner(ctx, name)
}

func (s *pgServer) openAsOwner(ctx context.Context, name string) (*db.DB, error) {
	if err := s.grant(ctx, name); err != nil {
		return nil, err
	}
	ownerURL, err := s.urlFor(name, s.logins.owner, s.logins.password)
	if err != nil {
		return nil, err
	}
	pool, _, err := db.OpenSQL(ctx, ownerURL, newConfig(), db.Connector(func(c driver.Connector) *sql.DB {
		return sql.OpenDB(setRole{Connector: c, role: s.roles.owner})
	}))
	if err != nil {
		return nil, err
	}
	return db.New(db.Postgres, pool), nil
}

func (s *pgServer) drop(ctx context.Context, name string) error {
	_, err := s.admin.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", quote(name)))
	return err
}

// janitor drops test databases and other templates left over from runs more than a day old.
func (s *pgServer) janitor(ctx context.Context, conn *sql.Conn, currentHash string) {
	found, err := databases(ctx, conn, s.roles.prefix+marker)
	if err != nil {
		return
	}
	now := clock.Wall(ctx).Now()
	for _, d := range found {
		if !expired(d.name, s.roles.prefix, currentHash, now) {
			continue
		}
		if d.template {
			_, _ = conn.ExecContext(ctx, fmt.Sprintf("ALTER DATABASE %s WITH IS_TEMPLATE false", quote(d.name))) // best effort
		}
		_, _ = conn.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", quote(d.name))) // best effort
	}
}

// dropUnfinished drops this hash's templates that a failed run left before marking them as templates.
func (s *pgServer) dropUnfinished(ctx context.Context, conn *sql.Conn, hash string) error {
	found, err := databases(ctx, conn, templateBase(s.roles.prefix, hash))
	if err != nil {
		return err
	}
	for _, d := range found {
		if g, ok := parseGenerated(d.name, s.roles.prefix); !ok || g.hash != hash || d.template {
			continue
		}
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", quote(d.name))); err != nil {
			return err
		}
	}
	return nil
}

type pgDatabase struct {
	name     string
	template bool
}

func databases(ctx context.Context, conn *sql.Conn, prefix string) ([]pgDatabase, error) {
	rows, err := conn.QueryContext(ctx, "SELECT datname, datistemplate FROM pg_database WHERE starts_with(datname, $1)", prefix)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []pgDatabase
	for rows.Next() {
		var d pgDatabase
		if err := rows.Scan(&d.name, &d.template); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// quote is for names testdb builds from its own prefix, hash and timestamp, never from input.
func quote(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }
