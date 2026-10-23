package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
)

func (d Dialect) String() string { return string(d) }

// DialectOf reads the dialect from a database URL's scheme.
func DialectOf(rawURL string) (Dialect, error) {
	scheme, _, ok := strings.Cut(rawURL, "://")
	if !ok {
		return "", errors.New("database URL must start with postgres:// or mysql://")
	}
	switch scheme {
	case "postgres", "postgresql":
		return Postgres, nil
	case "mysql":
		return MySQL, nil
	}
	return "", fmt.Errorf("database URL scheme %q is not postgres or mysql", scheme)
}

// Config is the database part of an app's configuration; field tags follow kit/config.
type Config struct {
	URL         config.Secret `env:"URL"`
	OperatorURL config.Secret `env:"OPERATOR_URL"`
	MigrateURL  config.Secret `env:"MIGRATE_URL"`
	CAFile      string        `env:"CA_FILE"`
	MaxOpen     int           `env:"MAX_OPEN" envDefault:"20"`
	// OperatorMaxOpen sizes the operator pool, which serves the operator realm and cross-tenant jobs only.
	OperatorMaxOpen  int           `env:"OPERATOR_MAX_OPEN" envDefault:"8"`
	MaxIdle          int           `env:"MAX_IDLE" envDefault:"10"`
	ConnLifetime     time.Duration `env:"CONN_LIFETIME" envDefault:"30m"`
	ConnIdleTime     time.Duration `env:"CONN_IDLE_TIME" envDefault:"5m"`
	StatementTimeout time.Duration `env:"STATEMENT_TIMEOUT" envDefault:"30s"`
	LockTimeout      time.Duration `env:"LOCK_TIMEOUT" envDefault:"10s"`
	IdleTxTimeout    time.Duration `env:"IDLE_TX_TIMEOUT" envDefault:"60s"`
}

// Defaults is the configuration with the documented defaults and no URLs, for tests and tools.
func Defaults() Config {
	return Config{
		MaxOpen: 20, OperatorMaxOpen: 8, MaxIdle: 10, ConnLifetime: 30 * time.Minute, ConnIdleTime: 5 * time.Minute,
		StatementTimeout: 30 * time.Second, LockTimeout: 10 * time.Second, IdleTxTimeout: time.Minute,
	}
}

// MigrateTarget is the URL migrations run with: the owner role, falling back to the app URL.
func (c Config) MigrateTarget() string {
	if c.MigrateURL != "" {
		return string(c.MigrateURL)
	}
	return string(c.URL)
}

func (c Config) Validate(prod bool) error {
	var errs []error
	if c.URL == "" {
		if prod {
			errs = append(errs, errors.New("database URL is required"))
		}
	}
	dialect, err := c.checkURL("database URL", string(c.URL), "", prod)
	if err != nil {
		errs = append(errs, err)
	}
	if _, err := c.checkURL("operator URL", string(c.OperatorURL), dialect, prod); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.checkURL("migrate URL", string(c.MigrateURL), dialect, prod); err != nil {
		errs = append(errs, err)
	}
	if prod {
		errs = append(errs, c.checkOwnerSeparate())
	}
	if c.MaxOpen < 1 {
		errs = append(errs, errors.New("max open must be at least 1"))
	}
	if c.OperatorMaxOpen < 1 || c.OperatorMaxOpen > c.MaxOpen {
		errs = append(errs, errors.New("operator max open must be between 1 and max open"))
	}
	if c.OperatorURL != "" && (c.OperatorURL == c.URL || userOf(string(c.OperatorURL)) == userOf(string(c.URL))) {
		errs = append(errs, errors.New("operator URL must connect as another role than the database URL (the operator role bypasses row-level security)"))
	}
	if _, err := loginRole(c.URL); err != nil {
		errs = append(errs, fmt.Errorf("database URL: %w", err))
	}
	if _, err := loginRole(c.OperatorURL); err != nil {
		errs = append(errs, fmt.Errorf("operator URL: %w", err))
	}
	if c.MaxIdle < 0 || c.MaxIdle > c.MaxOpen {
		errs = append(errs, errors.New("max idle must be between 0 and max open"))
	}
	if c.ConnLifetime < 0 || c.ConnIdleTime < 0 {
		errs = append(errs, errors.New("connection lifetime and idle time must not be negative"))
	}
	if c.StatementTimeout <= 0 || c.LockTimeout <= 0 || c.IdleTxTimeout <= 0 {
		errs = append(errs, errors.New("statement, lock and idle transaction timeouts must be positive"))
	}
	return errors.Join(errs...)
}

// ValidateMigrate checks only what migrations use: a target (the migrate URL, else the database URL;
// in production the migrate URL itself) with verified TLS in production, and the lock timeout. Deploys hand migrate the owner's URL alone.
func (c Config) ValidateMigrate(prod bool) error {
	target := c.MigrateTarget()
	switch {
	case prod && c.MigrateURL == "":
		return errors.New("migrate URL is required in production (the owner role runs migrations, not the app role)")
	case target == "":
		return errors.New("DATABASE_MIGRATE_URL or DATABASE_URL is required")
	}
	var errs []error
	if _, err := c.checkURL("migrate URL", target, "", prod); err != nil {
		errs = append(errs, err)
	}
	if c.LockTimeout <= 0 {
		errs = append(errs, errors.New("lock timeout must be positive"))
	}
	return errors.Join(errs...)
}

// checkOwnerSeparate keeps the owner role out of the running app in production: an app that owns its
// tables can turn row-level security off. serve is not handed the migrate URL; when both are set they
// must be different roles.
func (c Config) checkOwnerSeparate() error {
	if c.MigrateURL == "" {
		return nil
	}
	if c.MigrateURL == c.URL || userOf(string(c.MigrateURL)) == userOf(string(c.URL)) {
		return errors.New("migrate URL must connect as a different role from the database URL")
	}
	return nil
}

func userOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return ""
	}
	return u.User.Username()
}

// checkURL never echoes the URL: it carries a password.
func (c Config) checkURL(name, rawURL string, want Dialect, prod bool) (Dialect, error) {
	if rawURL == "" {
		return want, nil
	}
	d, err := DialectOf(rawURL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if want != "" && d != want {
		return "", fmt.Errorf("%s must use the same database engine as the database URL", name)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid URL", name)
	}
	if prod && !verifiesTLS(d, u.Query(), c.CAFile != "") {
		switch d {
		case Postgres:
			return "", fmt.Errorf("%s must set sslmode=verify-full in production", name)
		case MySQL:
			return "", fmt.Errorf("%s must set tls=true in production", name)
		}
	}
	return d, nil
}

// VerifiesTLS reports whether the database URL asks for a verified TLS connection.
func (c Config) VerifiesTLS() bool {
	d, err := DialectOf(string(c.URL))
	if err != nil {
		return false
	}
	u, err := url.Parse(string(c.URL))
	return err == nil && verifiesTLS(d, u.Query(), c.CAFile != "")
}

func verifiesTLS(d Dialect, q url.Values, haveCA bool) bool {
	switch d {
	case Postgres:
		return q.Get("sslmode") == "verify-full"
	case MySQL:
		return q.Get("tls") == "true" || (haveCA && q.Get("tls") == "")
	}
	return false
}

// DB holds the app pool and, when configured, the operator pool, which uses a role that bypasses row-level security.
type DB struct {
	dialect  Dialect
	app      *sql.DB
	operator *sql.DB
	hooks    *hookSet
	// appRole and operatorRole are the Postgres roles the pools log in as; Open records them.
	appRole, operatorRole string
	resetsTenant          bool
}

// OpenOption changes how Open and OpenSQL connect.
type OpenOption func(*openOptions)

type openOptions struct {
	resetTenant bool
	// pinSearchPath is Open's: the app and operator pools resolve unqualified names in public only.
	pinSearchPath bool
	open          func(driver.Connector) *sql.DB
}

// searchPath is the app and operator pools' search_path. Migrations keep the server's, since with
// pg_catalog first an unqualified create would target pg_catalog.
const searchPath = "pg_catalog, public"

func options(opts []OpenOption) openOptions {
	var o openOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func (o openOptions) sqlDB(c driver.Connector) *sql.DB {
	if o.open != nil {
		return o.open(c)
	}
	return sql.OpenDB(c)
}

// ResetTenant clears app.tenant_id on Postgres each time a pooled connection is handed out, so a
// session-level SET in one transaction never reaches the next borrower (tenancy, D30).
func ResetTenant() OpenOption { return func(o *openOptions) { o.resetTenant = true } }

// Connector makes the pool from the driver's connector with open instead of sql.OpenDB, so tracing can
// wrap it. open must keep the connection's own session reset and validity check (driver.SessionResetter,
// driver.Validator): ResetTenant relies on them.
func Connector(open func(driver.Connector) *sql.DB) OpenOption {
	return func(o *openOptions) { o.open = open }
}

// Open connects the app pool and, if an operator URL is set, the operator pool. The operator capability
// is nil without an operator URL; Open is the only place it is made (D29). On Postgres it refuses a URL
// whose startup parameters would change the role a pool acts as, preset an app.* setting or set the
// search path, and pins the search path to pg_catalog, public as a startup parameter, which outranks
// role and database defaults.
func Open(ctx context.Context, cfg Config, opts ...OpenOption) (*DB, *OperatorAccess, error) {
	opts = append(slices.Clip(opts), func(o *openOptions) { o.pinSearchPath = true })
	if cfg.URL == "" {
		return nil, nil, errors.New("database URL is not set")
	}
	appRole, err := loginRole(cfg.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("app pool: %w", err)
	}
	operatorRole, err := loginRole(cfg.OperatorURL)
	if err != nil {
		return nil, nil, fmt.Errorf("operator pool: %w", err)
	}
	app, dialect, err := OpenSQL(ctx, string(cfg.URL), cfg, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("app pool: %w", err)
	}
	d := New(dialect, app)
	d.appRole, d.operatorRole = appRole, operatorRole
	d.resetsTenant = dialect == Postgres && options(opts).resetTenant
	if cfg.OperatorURL == "" {
		return d, nil, nil
	}
	opCfg := cfg
	opCfg.MaxOpen, opCfg.MaxIdle = cfg.OperatorMaxOpen, min(cfg.MaxIdle, cfg.OperatorMaxOpen)
	op, opDialect, err := OpenSQL(ctx, string(cfg.OperatorURL), opCfg, opts...)
	if err != nil {
		_ = app.Close() // the open error is the one to report
		return nil, nil, fmt.Errorf("operator pool: %w", err)
	}
	if opDialect != dialect {
		_ = app.Close()
		_ = op.Close()
		return nil, nil, errors.New("operator URL must use the same database engine as the database URL")
	}
	d.operator = op
	return d, &OperatorAccess{d: d}, nil
}

// New wraps an already open app pool, for testdb and tools.
func New(dialect Dialect, app *sql.DB) *DB {
	return &DB{dialect: dialect, app: app, hooks: &hookSet{}}
}

func (d *DB) Dialect() Dialect { return d.dialect }

// LoginRole is the Postgres role the app pool logs in as, from its URL; empty for a pool made with New.
func (d *DB) LoginRole() string { return d.appRole }

// ResetsTenant is true when Open made the Postgres app pool with ResetTenant; the tenancy part needs it.
func (d *DB) ResetsTenant() bool { return d.resetsTenant }

// SQL is the app pool, for kit infrastructure and tooling that works below transactions; lint forbids it
// outside internal/kit, cmd and tests.
func (d *DB) SQL() *sql.DB { return d.app }

func (d *DB) Close() error {
	errs := []error{d.app.Close()}
	if d.operator != nil {
		errs = append(errs, d.operator.Close())
	}
	return errors.Join(errs...)
}

// OpenSQL opens and pings one pool for rawURL with the session settings, TLS policy and pool limits in cfg.
func OpenSQL(ctx context.Context, rawURL string, cfg Config, opts ...OpenOption) (*sql.DB, Dialect, error) {
	dialect, err := DialectOf(rawURL)
	if err != nil {
		return nil, "", err
	}
	o := options(opts)
	var tlsRoots *x509.CertPool
	if cfg.CAFile != "" {
		if tlsRoots, err = loadCA(cfg.CAFile); err != nil {
			return nil, "", err
		}
	}
	var pool *sql.DB
	switch dialect {
	case Postgres:
		pool, err = openPostgres(rawURL, cfg, tlsRoots, o)
	case MySQL:
		pool, err = openMySQL(rawURL, cfg, tlsRoots, o)
	}
	if err != nil {
		return nil, "", err
	}
	pool.SetMaxOpenConns(cfg.MaxOpen)
	pool.SetMaxIdleConns(cfg.MaxIdle)
	pool.SetConnMaxLifetime(jitter(cfg.ConnLifetime))
	pool.SetConnMaxIdleTime(cfg.ConnIdleTime)
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close() // the ping error is the one to report
		return nil, "", fmt.Errorf("connect to %s: %w", dialect, err)
	}
	return pool, dialect, nil
}

// jitter shortens the lifetime by up to 10 percent so replicas do not recycle connections in step.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d - time.Duration(rand.Int64N(int64(d)/10+1)) //nolint:gosec // spread, not secrecy
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("read database CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("database CA file holds no PEM certificates")
	}
	return pool, nil
}

func millis(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

func openPostgres(rawURL string, cfg Config, roots *x509.CertPool, o openOptions) (*sql.DB, error) {
	conf, err := pgx.ParseConfig(rawURL)
	if err != nil {
		return nil, errors.New("database URL is not a valid Postgres connection string")
	}
	conf.RuntimeParams["timezone"] = "UTC"
	conf.RuntimeParams["statement_timeout"] = millis(cfg.StatementTimeout)
	conf.RuntimeParams["lock_timeout"] = millis(cfg.LockTimeout)
	conf.RuntimeParams["idle_in_transaction_session_timeout"] = millis(cfg.IdleTxTimeout)
	if o.pinSearchPath {
		conf.RuntimeParams["search_path"] = searchPath
	}
	if roots != nil {
		if conf.TLSConfig == nil {
			return nil, errors.New("a database CA file needs sslmode=verify-full")
		}
		conf.TLSConfig.RootCAs = roots
		for _, fb := range conf.Fallbacks {
			if fb.TLSConfig != nil {
				fb.TLSConfig.RootCAs = roots
			}
		}
	}
	if !o.resetTenant {
		return o.sqlDB(stdlib.GetConnector(*conf)), nil
	}
	// The reset is a round trip that also proves the connection alive, so the idle ping is skipped.
	return o.sqlDB(stdlib.GetConnector(*conf, stdlib.OptionResetSession(resetTenant),
		stdlib.OptionShouldPing(func(context.Context, stdlib.ShouldPingParams) bool { return false }))), nil
}

// loginRole is the role a Postgres URL logs in as (empty for any other URL). It refuses startup parameters,
// in the URL or in PGOPTIONS, that would make the session act as another role (RESET ROLE would then return
// to the login, which CheckRoles never saw), start with an app.* setting before any reset has run, or
// point unqualified names at another schema than public.
func loginRole(rawURL config.Secret) (string, error) {
	if d, _ := DialectOf(string(rawURL)); d != Postgres {
		return "", nil
	}
	conf, err := pgx.ParseConfig(string(rawURL))
	if err != nil {
		return "", nil //nolint:nilerr // OpenSQL reports the URL itself
	}
	for name, value := range conf.RuntimeParams {
		if name == "options" {
			err = errors.Join(err, checkStartupOptions(value))
			continue
		}
		err = errors.Join(err, checkStartupSetting(name))
	}
	return conf.User, err
}

// checkStartupOptions reads options as the server does: -c name=value, -cname=value or --name=value.
func checkStartupOptions(options string) error {
	if strings.Contains(options, `\`) {
		return errors.New("the options startup parameter may not hold backslash escapes")
	}
	fields := strings.Fields(options)
	var errs []error
	for i := 0; i < len(fields); i++ {
		setting, ok := "", false
		switch f := fields[i]; {
		case f == "-c" && i+1 < len(fields):
			i++
			setting, ok = fields[i], true
		case strings.HasPrefix(f, "--"):
			name, value, found := strings.Cut(f[2:], "=")
			setting, ok = strings.ReplaceAll(name, "-", "_")+"="+value, found
		case strings.HasPrefix(f, "-c"):
			setting, ok = f[2:], true
		}
		name, _, found := strings.Cut(setting, "=")
		if !ok || !found {
			errs = append(errs, errors.New("the options startup parameter may only set -c name=value"))
			continue
		}
		errs = append(errs, checkStartupSetting(name))
	}
	return errors.Join(errs...)
}

func checkStartupSetting(name string) error {
	switch n := strings.ToLower(name); {
	case n == "role", n == "session_authorization":
		return fmt.Errorf("a startup %s would make the pool act as another role than it logs in as; log in as that role", n)
	case strings.HasPrefix(n, "app."):
		return fmt.Errorf("a startup %s would preset a setting only kit/db writes", n)
	case n == "search_path":
		return errors.New("a startup search_path would resolve the app's tables in another schema; kit/db pins it to pg_catalog, public")
	}
	return nil
}

func resetTenant(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, "select set_config('app.tenant_id', '', false)"); err != nil {
		return driver.ErrBadConn
	}
	return nil
}

const mysqlSQLMode = "'ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"

func openMySQL(rawURL string, cfg Config, roots *x509.CertPool, o openOptions) (*sql.DB, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User == nil || u.User.Username() == "" {
		return nil, errors.New("database URL is not a valid MySQL URL (mysql://user:password@host:port/database)")
	}
	conf := mysql.NewConfig()
	conf.User = u.User.Username()
	conf.Passwd, _ = u.User.Password()
	conf.Net = "tcp"
	conf.Addr = u.Host
	if u.Port() == "" {
		conf.Addr = net.JoinHostPort(u.Hostname(), "3306")
	}
	conf.DBName = strings.TrimPrefix(u.Path, "/")
	conf.ParseTime = true
	conf.Loc = time.UTC
	conf.MultiStatements = false
	conf.InterpolateParams = false
	conf.Collation = "utf8mb4_0900_ai_ci"
	conf.Params = map[string]string{
		"time_zone":                "'+00:00'",
		"sql_mode":                 mysqlSQLMode,
		"innodb_lock_wait_timeout": strconv.FormatInt(max(1, int64(cfg.LockTimeout.Round(time.Second)/time.Second)), 10),
		"max_execution_time":       millis(cfg.StatementTimeout),
	}
	for key, values := range u.Query() {
		if key != "tls" {
			return nil, fmt.Errorf("database URL parameter %q is not supported for MySQL", key)
		}
		switch mode := values[0]; mode {
		case "true":
			conf.TLS = &tls.Config{ServerName: u.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS12}
		case "skip-verify", "preferred", "false":
			conf.TLSConfig = mode
		default:
			return nil, fmt.Errorf("database URL tls=%q must be true, skip-verify, preferred or false", mode)
		}
	}
	if roots != nil && conf.TLS == nil && conf.TLSConfig == "" {
		conf.TLS = &tls.Config{ServerName: u.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	connector, err := mysql.NewConnector(conf)
	if err != nil {
		return nil, fmt.Errorf("mysql connector: %w", err)
	}
	return o.sqlDB(connector), nil
}
