package testdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

// readyTable marks a finished MySQL template; MySQL has no transactional DDL to make the build atomic.
const readyTable = "testdb_ready"

type myServer struct {
	adminURL string
	pfx      string
	admin    *sql.DB
	// user is this run's login for test databases: per table, the DML a production app user is granted.
	// The admin only creates databases and migrates.
	user, password string
}

func (s *myServer) dialect() db.Dialect { return db.MySQL }
func (s *myServer) prefix() string      { return s.pfx }

func (s *myServer) open(ctx context.Context) error {
	admin, _, err := db.OpenSQL(ctx, s.adminURL, newConfig())
	if err != nil {
		return err
	}
	s.admin = admin
	return nil
}

func (s *myServer) close() {
	if s.admin == nil {
		return
	}
	if s.user != "" {
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		if _, err := s.admin.ExecContext(ctx, "DROP USER IF EXISTS "+account(s.user)); err != nil {
			fmt.Fprintf(os.Stderr, "testdb: drop user %s: %v\n", s.user, err)
		}
	}
	_ = s.admin.Close() // nothing left to do with the error at teardown
}

// urlFor points the admin URL at database name, logging in as user when one is given.
func (s *myServer) urlFor(name, user, password string) (string, error) {
	u, err := url.Parse(s.adminURL)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid URL", MySQLURLVar)
	}
	u.Path = "/" + name
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	return u.String(), nil
}

// userShape is a run's login: <prefix>_t<8 hex>, within MySQL's 32-character user names.
var userShape = regexp.MustCompile(`^_t[0-9a-f]{8}$`)

// ensureUser makes this run's login once, and drops logins a run more than a day old left behind.
func (s *myServer) ensureUser(ctx context.Context, conn *sql.Conn) error {
	if s.user != "" {
		return nil
	}
	rows, err := conn.QueryContext(ctx, "SELECT user FROM mysql.user WHERE LEFT(user, CHAR_LENGTH(?)) = ? AND password_last_changed < ?",
		s.pfx, s.pfx, clock.Wall(ctx).Now().UTC().Add(-maxAge))
	if err == nil {
		stale, _ := collect(rows)
		for _, name := range stale {
			if userShape.MatchString(strings.TrimPrefix(name, s.pfx)) {
				_, _ = conn.ExecContext(ctx, "DROP USER IF EXISTS "+account(name)) // best effort
			}
		}
	}
	user, password := s.pfx+"_t"+randomHex(4), randomHex(16)
	if _, err := conn.ExecContext(ctx, "CREATE USER "+account(user)+" IDENTIFIED BY '"+password+"'"); err != nil {
		return fmt.Errorf("test user: %w", err)
	}
	s.user, s.password = user, password
	return nil
}

// grant gives the run's login, on every table of database name, what deploy grants the app user:
// select, insert, update and delete, with audit_log append-only.
func (s *myServer) grant(ctx context.Context, name string) error {
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	tables, err := s.tables(ctx, conn, name)
	if err != nil {
		return err
	}
	for _, table := range tables {
		privileges := "SELECT, INSERT, UPDATE, DELETE"
		if table == "audit_log" {
			privileges = "SELECT, INSERT"
		}
		if _, err := conn.ExecContext(ctx, "GRANT "+privileges+" ON "+quoteMy(name)+"."+quoteMy(table)+" TO "+account(s.user)); err != nil {
			return fmt.Errorf("grant %s: %w", table, err)
		}
	}
	return nil
}

func (s *myServer) ensureTemplate(ctx context.Context, hash string, migrations fs.FS, tpl *Template) (string, error) {
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	key := s.pfx + ":testdb"
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 120)", key).Scan(&got); err != nil || got.Int64 != 1 {
		return "", errors.Join(errors.New("lock: timed out"), err)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "DO RELEASE_LOCK(?)", key) }()

	s.janitor(ctx, conn, hash)
	if err := s.ensureUser(ctx, conn); err != nil {
		return "", err
	}
	names, err := s.schemas(ctx, conn, templateBase(s.pfx, hash))
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if g, ok := parseGenerated(name, s.pfx); !ok || g.hash != hash {
			continue
		}
		var ready bool
		if err := conn.QueryRowContext(ctx,
			"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", name, readyTable).Scan(&ready); err != nil {
			return "", err
		}
		if ready {
			return name, nil
		}
		if err := s.drop(ctx, name); err != nil {
			return "", err
		}
	}
	name := templateName(s.pfx, hash, clock.Wall(ctx).Now())
	if err := s.build(ctx, name, migrations, tpl); err != nil {
		return "", err
	}
	return name, nil
}

func (s *myServer) build(ctx context.Context, name string, migrations fs.FS, tpl *Template) error {
	if _, err := s.admin.ExecContext(ctx, "CREATE DATABASE "+quoteMy(name)); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	target, err := s.urlFor(name, "", "")
	if err != nil {
		return err
	}
	pool, _, err := db.OpenSQL(ctx, target, newConfig())
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()
	if _, err := migrate.New(pool, db.MySQL, migrations, migrate.Options{}).Up(ctx); err != nil {
		return err
	}
	if tpl != nil {
		if err := tpl.prepare(ctx, db.New(db.MySQL, pool)); err != nil {
			return fmt.Errorf("prepare %s: %w", tpl.name, err)
		}
	}
	_, err = pool.ExecContext(ctx, "CREATE TABLE "+readyTable+" (id int)")
	return err
}

// clone copies every table with its definition (SHOW CREATE TABLE keeps foreign keys, which
// CREATE TABLE ... LIKE drops) and its rows. A failed clone is dropped.
func (s *myServer) clone(ctx context.Context, template, name string) (err error) {
	if _, err := s.admin.ExecContext(ctx, "CREATE DATABASE "+quoteMy(name)); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = s.drop(context.WithoutCancel(ctx), name) // the clone error is the one to report
		}
	}()
	target, err := s.urlFor(name, "", "")
	if err != nil {
		return err
	}
	cfg := newConfig()
	cfg.MaxOpen, cfg.MaxIdle = 1, 1
	pool, _, err := db.OpenSQL(ctx, target, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()
	conn, err := pool.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	tables, err := s.tables(ctx, conn, template)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		return err
	}
	for _, table := range tables {
		var ignored, create string
		if err := conn.QueryRowContext(ctx, "SHOW CREATE TABLE "+quoteMy(template)+"."+quoteMy(table)).Scan(&ignored, &create); err != nil {
			return fmt.Errorf("show create %s: %w", table, err)
		}
		if _, err := conn.ExecContext(ctx, create); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
		copyRows := "INSERT INTO " + quoteMy(table) + " SELECT * FROM " + quoteMy(template) + "." + quoteMy(table) //nolint:gosec // quoted identifiers from information_schema
		if _, err := conn.ExecContext(ctx, copyRows); err != nil {
			return fmt.Errorf("copy %s: %w", table, err)
		}
	}
	_, err = conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	return err
}

func (s *myServer) tables(ctx context.Context, conn *sql.Conn, schema string) ([]string, error) {
	rows, err := conn.QueryContext(ctx,
		"SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' AND table_name <> ?",
		schema, readyTable)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

func (s *myServer) schemas(ctx context.Context, conn *sql.Conn, prefix string) ([]string, error) {
	rows, err := conn.QueryContext(ctx,
		"SELECT schema_name FROM information_schema.schemata WHERE LEFT(schema_name, CHAR_LENGTH(?)) = ?", prefix, prefix)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// connect logs in to a cloned database as the run's login, with its grants on the clone's tables.
func (s *myServer) connect(ctx context.Context, name string) (*db.DB, error) {
	if err := s.grant(ctx, name); err != nil {
		return nil, err
	}
	return s.login(ctx, name, s.user, s.password)
}

func (s *myServer) owner(ctx context.Context, name string) (*db.DB, error) {
	return s.login(ctx, name, "", "")
}

func (s *myServer) login(ctx context.Context, name, user, password string) (*db.DB, error) {
	target, err := s.urlFor(name, user, password)
	if err != nil {
		return nil, err
	}
	pool, _, err := db.OpenSQL(ctx, target, newConfig())
	if err != nil {
		return nil, err
	}
	return db.New(db.MySQL, pool), nil
}

func (s *myServer) empty(ctx context.Context, name string) (*db.DB, error) {
	if _, err := s.admin.ExecContext(ctx, "CREATE DATABASE "+quoteMy(name)); err != nil {
		return nil, err
	}
	d, err := s.login(ctx, name, "", "")
	if err != nil {
		_ = s.drop(ctx, name) // the connect error is the one to report
		return nil, err
	}
	return d, nil
}

func (s *myServer) drop(ctx context.Context, name string) error {
	_, err := s.admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteMy(name))
	return err
}

func (s *myServer) janitor(ctx context.Context, conn *sql.Conn, currentHash string) {
	names, err := s.schemas(ctx, conn, s.pfx+marker)
	if err != nil {
		return
	}
	now := clock.Wall(ctx).Now()
	for _, name := range names {
		if expired(name, s.pfx, currentHash, now) {
			_ = s.drop(ctx, name) // best effort; the next run tries again
		}
	}
}

func collect(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func quoteMy(ident string) string { return "`" + strings.ReplaceAll(ident, "`", "``") + "`" }

// account is a test login from any host: the server sees the container network's address.
func account(user string) string { return quoteMy(user) + "@'%'" }
