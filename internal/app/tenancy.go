//go:build !notenancy

// Every use of kit/tenancy in internal/app is in this file; tenancy_off.go has the same names for a
// build without the part (go build -tags notenancy, which keel init makes the default when it drops it).

package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// RealmOperator is the people who run the service (tenancy): its own hosts, cookie, catalogue and
// required second factor, and the only realm whose operations get the operator pool.
const RealmOperator = "operator"

const (
	PermTenantsRead    rbac.Code = "tenants.read"
	PermTenantsManage  rbac.Code = "tenants.manage"
	PermTenantsSuspend rbac.Code = "tenants.suspend"
	PermUsersRead      rbac.Code = "users.read"
)

var operatorCatalogue = rbac.NewCatalogue(
	rbac.Perm{
		Code: PermAccessManage, Area: "Access", Label: "Manage operator access",
		Description: "Give or take operator roles", Sensitive: true,
	},
	rbac.Perm{Code: PermTenantsRead, Area: "Tenants", Label: "See tenants", Description: "List tenants and read their audit trail"},
	rbac.Perm{Code: PermTenantsManage, Area: "Tenants", Label: "Create tenants", Description: "Create tenants and their owners", Sensitive: true},
	rbac.Perm{Code: PermTenantsSuspend, Area: "Tenants", Label: "Suspend tenants", Description: "Suspend and resume tenants", Sensitive: true},
	rbac.Perm{Code: PermUsersRead, Area: "Users", Label: "See users", Description: "Look up users across tenants"},
)

// ownerRole is the template role a new tenant's first user holds.
const ownerRole = "admin"

const (
	operatorCookie   = "operator_session"
	operatorIdle     = 30 * time.Minute
	operatorAbsolute = 8 * time.Hour
	// operatorPlaceholderHost stands in for APP_REALM_OPERATOR_HOSTS where operations are listed without configuration.
	operatorPlaceholderHost = "operator.invalid"
)

// TenancyConfig is APP_TENANCY_*.
type TenancyConfig = tenancy.Config

// tenancyWiring is set with a database under tenancy; only operator-realm operations use operator.
type tenancyWiring struct {
	tenancy  *tenancy.Service
	operator *db.OperatorAccess
}

// appGlobalTables are this app's global tables, shared by every tenant, each with the reason; their
// migrations say -- keel:global with the same reason. Indexes and policies that break the tenant
// rules on purpose go here too (tenancy.Exception).
var appGlobalTables = []tenancy.Exception{}

// operatorRealms are the realms the tenancy part adds, on a placeholder host, for route listings.
func operatorRealms() []realm.Realm {
	return []realm.Realm{operatorRealm([]string{operatorPlaceholderHost})}
}

func operatorRealm(hosts []string) realm.Realm {
	return realm.Realm{Name: RealmOperator, Hosts: hosts, BasePath: BasePath, Catalogue: operatorCatalogue}
}

// operatorBuiltins are the operator realm's roles, made by `app setup` on the operator pool.
var operatorBuiltins = []rbac.Builtin{
	{Code: "operator", Name: "Operator", Permissions: []rbac.Code{PermAccessManage, PermTenantsRead, PermTenantsManage, PermTenantsSuspend, PermUsersRead}},
}

// configuredOperator is the operator realm when it has hosts: its block over the realm's own defaults.
func configuredOperator(cfg Config) (realm.Realm, bool) {
	b := cfg.Realm.Operator
	if len(b.Hosts) == 0 {
		return realm.Realm{}, false
	}
	r := operatorRealm(b.Hosts)
	r.Cookie, r.Idle, r.Absolute, r.MFA = operatorCookie, operatorIdle, operatorAbsolute, realm.MFARequired
	if b.Cookie != "" {
		r.Cookie = b.Cookie
	}
	if b.Idle > 0 {
		r.Idle = b.Idle
	}
	if b.Absolute > 0 {
		r.Absolute = b.Absolute
	}
	if b.MFA != "" {
		r.MFA = b.MFA
	}
	r.Loader = rbac.NewLoader(RealmOperator, operatorCatalogue)
	return r, true
}

// tenancyPart reports whether this app keeps the tenancy part on dialect: its migrations ship with it.
func tenancyPart(d db.Dialect) bool {
	fsys, err := migrations.For(d)
	if err != nil {
		return false
	}
	names, _ := fs.Glob(fsys, "*_tenancy_*.sql")
	return len(names) > 0
}

// operatorReserve is the operator pool left over for lease renewals, the reaper and operator requests
// when every worker holds a connection.
const operatorReserve = 2

// validateTenancy refuses tenancy settings with MySQL (no row-level security, D16), and in production a
// tenancy app without the operator pool or an operator realm without a required second factor.
func (c Config) validateTenancy() error {
	dialect, _ := db.DialectOf(string(c.Database.URL))
	var errs []error
	if dialect == db.MySQL && (c.Tenancy.Set() || len(c.Realm.Operator.Hosts) > 0 || c.Database.OperatorURL != "") {
		errs = append(errs, errors.New("tenancy needs Postgres: with MySQL leave APP_TENANCY_*, APP_REALM_OPERATOR_HOSTS and APP_DATABASE_OPERATOR_URL unset"))
	}
	if dialect == db.Postgres && tenancyPart(dialect) && c.Env.IsProd() && c.Database.OperatorURL == "" {
		errs = append(errs, errors.New("tenancy needs APP_DATABASE_OPERATOR_URL (a role with bypassrls) for operators and cross-tenant jobs"))
	}
	if workers := c.Jobs.Workers(); dialect == db.Postgres && tenancyPart(dialect) && c.Database.OperatorURL != "" && c.Database.OperatorMaxOpen < workers+operatorReserve {
		errs = append(errs, fmt.Errorf("APP_DATABASE_OPERATOR_MAX_OPEN is %d: under tenancy job workers claim and run on the operator pool, so it needs at least the %d workers plus %d",
			c.Database.OperatorMaxOpen, workers, operatorReserve))
	}
	if r, ok := configuredOperator(c); ok && c.Env.IsProd() && r.MFA != realm.MFARequired {
		errs = append(errs, errors.New("the operator realm's MFA must be required in production"))
	}
	return errors.Join(errs...)
}

func refuseOperator(Config) error { return nil }

// operatorModuleCommands are the modules' cross-tenant commands; only this part hands out the operator pool.
func operatorModuleCommands(environ []string, list []Module) []cli.Command {
	open := func(ctx context.Context) (*db.DB, *db.OperatorAccess, func(), error) {
		_, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return nil, nil, nil, err
		}
		if deps.Operator == nil {
			_ = deps.DB.Close()
			return nil, nil, nil, errors.New("this command needs APP_DATABASE_OPERATOR_URL (a role with bypassrls)")
		}
		return deps.DB, deps.Operator, func() { _ = deps.DB.Close() }, nil
	}
	var out []cli.Command
	for _, m := range list {
		if om, ok := m.(OperatorModule); ok {
			out = append(out, om.OperatorCommands(open)...)
		}
	}
	return out
}

// openOptions are the database options the tenancy part needs: the tenant setting cleared on every
// connection handed out.
func openOptions(cfg Config) []db.OpenOption {
	if d, err := db.DialectOf(string(cfg.Database.URL)); err == nil && tenancyPart(d) {
		return []db.OpenOption{db.ResetTenant()}
	}
	return nil
}

// startTenancy runs as the database opens: it refuses a database and a build that disagree about the
// tenancy part, then installs the tenant transaction hooks and checks the roles and the schema.
func startTenancy(ctx context.Context, deps *Deps) error {
	deps.Tenancy = tenancyPart(deps.DB.Dialect())
	if err := matchTenancySchema(ctx, deps.DB, deps.Tenancy); err != nil || !deps.Tenancy {
		return err
	}
	if err := tenancy.Install(deps.DB); err != nil {
		return err
	}
	return CheckTenancy(ctx, *deps)
}

// CheckTenancy runs at startup: it refuses pools whose roles could step around row-level security and
// logs tables that break the schema rules (the catalogue test fails on them in CI).
func CheckTenancy(ctx context.Context, deps Deps) error {
	if deps.Operator == nil {
		return errors.New("the tenancy part needs APP_DATABASE_OPERATOR_URL (a role with bypassrls)")
	}
	if err := tenancy.CheckRoles(ctx, deps.DB, deps.Operator); err != nil {
		return err
	}
	if err := CheckSchema(ctx, deps.DB); err != nil {
		logx.From(ctx).Warn("tables break the tenancy schema rules", "error", err)
	}
	return nil
}

// CheckSchema runs the catalogue check (docs/tenancy.md section 4) with the app's exceptions on the
// migrated schema, kit and modules alike.
func CheckSchema(ctx context.Context, d *db.DB) error {
	return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		return tenancy.CheckCatalogue(ctx, tx, appGlobalTables...)
	}, db.ReadOnly())
}

// appProcedural are this app's migrations allowed to run procedural SQL under tenancy (a DO block, or a
// function that runs dynamic SQL or changes tables, policies or row-level security), each with the reason
// its file gives after -- keel:procedural.
var appProcedural = []migrate.Procedural{}

// checkMigrated runs the catalogue check on the migrate connection once migrate has applied the files: a
// finding fails the command, so a deploy stops before the new release serves the schema.
func checkMigrated(ctx context.Context, d *db.DB) error {
	if d.Dialect() != db.Postgres || !tenancyPart(d.Dialect()) {
		return nil
	}
	if err := CheckSchema(ctx, d); err != nil {
		return fmt.Errorf("the migrations are applied, but the schema breaks the tenancy rules (docs/tenancy.md section 4); fix it in a new migration before this release serves:\n%w", err)
	}
	return nil
}

// allowedMigrations are the policies besides the tenant policy, and the procedural SQL, migrate:validate accepts.
func allowedMigrations() migrate.Allowed {
	return migrate.Allowed{
		Policies:   tenancy.AllowedPolicies(appGlobalTables...),
		Procedural: append(append([]migrate.Procedural(nil), tenancy.KitProcedural...), appProcedural...),
	}
}

// checkGlobalTables is migrate:validate's half of the global rule: every table a Postgres migration
// marks global is on the allowlist too.
func checkGlobalTables(fsys fs.FS, d db.Dialect) error {
	if d != db.Postgres || !tenancyPart(d) {
		return nil
	}
	marked, err := migrate.GlobalTables(fsys)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, e := range append(append([]tenancy.Exception(nil), tenancy.KitExceptions...), appGlobalTables...) {
		if e.Global() {
			allowed[e.Table] = true
		}
	}
	var errs []error
	for table := range marked {
		if !allowed[table] {
			errs = append(errs, fmt.Errorf("table %s is marked -- keel:global but is not in appGlobalTables (internal/app/tenancy.go)", table))
		}
	}
	return errors.Join(errs...)
}

// readOnlyAllowed are operations a read-only tenant still serves: signing in and out, switching away,
// the second factor, account links and leak reports. Anything else unsafe, public or not, is refused.
var readOnlyAllowed = []string{
	"signIn", "devLogin", "beginPasskeySignIn", "finishPasskeySignIn", "signOut", "switchTenant",
	"enrolTotp", "confirmTotp", "verifyTotp", "useRecoveryCode",
	"requestPasswordReset", "resetPassword", "verifyEmail", "acceptInvite", "reportLeakedApiKeys",
}

// nonMemberAllowed are operations a signed-in person may call in a tenant they are not a member of.
var nonMemberAllowed = []string{"signOut"}

// reservedHosts are the hosts no tenant's custom domain may take.
func reservedHosts(cfg Config) []string {
	hosts := append(append(append([]string(nil), cfg.Realm.Tenant.Hosts...), apiHosts(cfg)...), cfg.Realm.Operator.Hosts...)
	if u, err := url.Parse(cfg.App.PublicURL); err == nil && u.Host != "" {
		hosts = append(hosts, u.Host)
	}
	return hosts
}

func (w *wiring) setupTenancy(cfg Config, deps Deps) error {
	if !deps.Tenancy || deps.DB == nil {
		return nil
	}
	var err error
	w.operator = deps.Operator
	w.tenancy, err = tenancy.New(tenancy.Options{
		DB: deps.DB, Config: cfg.Tenancy, Audit: w.audit, Realm: RealmTenant, Catalogue: tenantCatalogue,
		Templates: builtinRoles[RealmTenant], Owner: ownerRole, AllowReadOnly: readOnlyAllowed,
		AllowNonMember: nonMemberAllowed, ReservedHosts: reservedHosts(cfg),
	})
	return err
}

// sessionTenancy is the tenancy part's say in sign-in, nil without it.
func (w *wiring) sessionTenancy() auth.Tenancy {
	if w.tenancy == nil {
		return nil
	}
	return w.tenancy
}

func passThrough(hctx huma.Context, next func(huma.Context)) { next(hctx) }

// resolveTenant and guardTenant are the tenancy middlewares (docs/architecture.md section 5): the host's
// tenant before the session, membership and access state after it.
func (w *wiring) resolveTenant(realmName string, api huma.API) func(huma.Context, func(huma.Context)) {
	if w.tenancy == nil || realmName != RealmTenant {
		return passThrough
	}
	return w.tenancy.Resolve(api)
}

func (w *wiring) guardTenant(realmName string, api huma.API, principals rbac.Principals) func(huma.Context, func(huma.Context)) {
	if w.tenancy == nil || realmName == RealmOperator {
		return passThrough
	}
	return w.tenancy.Guard(api, principals)
}

// memberHere reports whether user may be acted on in the request's tenant: always without one, else
// when they are its member. Account links on a tenant's host serve only its members.
func (w *wiring) memberHere(ctx context.Context, tx db.Transaction, user users.ID) (bool, error) {
	id, ok := db.TenantOf(ctx)
	if w.tenancy == nil || !ok {
		return true, nil
	}
	return tenancy.IsMember(ctx, tx, tenancy.ID(id), user)
}

// linkTenant reports whether a public file link of tenant id may serve here, before the link's tenant
// becomes the context's: not on another tenant's host, nor of a tenant that is suspended or gone.
func (w *wiring) linkTenant(ctx context.Context, id uuid.UUID) (bool, error) { //nolint:unused // a hook files.go calls; unused in an app without files
	if w.tenancy == nil || id == uuid.Nil {
		return true, nil
	}
	if host, ok := tenancy.HostTenant(ctx); ok && host != id {
		return false, nil
	}
	var t tenancy.Tenant
	err := db.InTx(ctx, w.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		t, err = tenancy.Get(ctx, tx, tenancy.ID(id))
		return err
	}, db.ReadOnly())
	if errors.Is(err, tenancy.ErrNotFound) {
		return false, nil
	}
	return err == nil && t.Status != tenancy.Suspended, err
}

var errNoTenancy = problem.New(http.StatusNotFound, problem.CodeNotFound, "tenancy is not enabled")

func (w *wiring) tenancyReady() error {
	if err := w.ready(); err != nil {
		return err
	}
	if w.tenancy == nil {
		return errNoTenancy
	}
	return nil
}

var tagTenants = []string{"tenants"}

type switchTenantInput struct {
	Body struct {
		TenantID string `json:"tenantId" format:"uuid"`
	}
}

// Switched is the session after a tenant switch: rotated, so a bearer client stores the new token (the
// old one stops working) and a browser gets a new cookie.
type Switched struct {
	Tenant  tenancy.Tenant `json:"tenant"`
	Session SignedIn       `json:"session"`
}

// registerTenancy adds the tenant realm's own tenancy operations; they answer 404 without tenancy.
func (w *wiring) registerTenancy(api huma.API) {
	httpx.Register(api, huma.Operation{OperationID: "listMyTenants", Method: http.MethodGet, Path: "/me/tenants", Summary: "The tenants you may work in", Tags: tagTenants},
		w.listMyTenants, rbac.SignedIn(), ratelimit.Class(ratelimit.ClassAPIRead))
	httpx.Register(api, huma.Operation{OperationID: "switchTenant", Method: http.MethodPost, Path: "/auth/tenant", Summary: "Work in another of your tenants; the session rotates", Tags: tagAuth},
		w.switchTenant, rbac.SignedIn(), authClass)
}

func (w *wiring) listMyTenants(ctx context.Context, _ *struct{}) (*httpx.List[tenancy.Membership], error) {
	if err := w.tenancyReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	var out []tenancy.Membership
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out, err = tenancy.Memberships(ctx, tx, s.UserID)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []tenancy.Membership{}
	}
	return httpx.ListOf(out, httpx.ListMeta{Limit: len(out)}, httpx.Links{}), nil
}

// switchTenant moves the session to another tenant the user is a member of, rotating it.
func (w *wiring) switchTenant(ctx context.Context, in *switchTenantInput) (*httpx.One[Switched], error) {
	if err := w.tenancyReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	id, err := tenancy.ParseID(in.Body.TenantID)
	if err != nil {
		return nil, tenancy.ErrNotAMember
	}
	var out Switched
	err = db.InTx(db.WithTenant(ctx, id.UUID()), w.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		t, err := w.tenancy.Enter(ctx, tx, id, s.UserID)
		if err != nil {
			return err
		}
		started, err := w.sessions.Switch(tenancy.WithTenant(ctx, t), tx, t.ID.UUID())
		out = Switched{Tenant: t, Session: signedIn(started)}
		return err
	})
	return one(out, err)
}

// operatorTx is how operator operations reach the database: the operator pool, under tenancy only.
func (w *wiring) operatorTx(ctx context.Context, fn func(ctx context.Context, tx db.Tx[db.Operator]) error, opts ...db.TxOption) error {
	if err := w.tenancyReady(); err != nil {
		return err
	}
	return db.InOperatorTx(ctx, w.operator, fn, opts...)
}

type listTenantsInput struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"100" default:"50"`
	Cursor string `query:"cursor" maxLength:"64" doc:"The slug the previous page ended on"`
}

type createTenantInput struct {
	Body struct {
		Slug       string   `json:"slug" minLength:"1" maxLength:"63" doc:"Lower-case letters, digits and -; names the tenant's host under the suffix"`
		Name       string   `json:"name" minLength:"1" maxLength:"200"`
		OwnerEmail string   `json:"ownerEmail" maxLength:"254" doc:"An existing user; they become a member holding the owner role"`
		Domains    []string `json:"domains,omitempty" maxItems:"10" doc:"Custom domains that resolve to the tenant"`
	}
}

type tenantStateInput struct {
	TenantID string `path:"tenantId" format:"uuid"`
	Body     struct {
		Reason string `json:"reason,omitempty" maxLength:"200"`
	}
}

type tenantAuditInput struct {
	TenantID string `path:"tenantId" format:"uuid"`
	Limit    int    `query:"limit" minimum:"1" maximum:"100" default:"50"`
	Before   int64  `query:"before" minimum:"0" doc:"Rows older than this seq; 0 starts at the newest"`
}

func (w *wiring) registerOperator(api huma.API) {
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tagTenants}
	}
	read, write := ratelimit.Class(ratelimit.ClassAPIRead), ratelimit.Class(ratelimit.ClassAPIWrite)
	httpx.Register(api, op("listTenants", http.MethodGet, "/tenants", "List tenants by slug"), w.listTenants, rbac.Requires(PermTenantsRead), read)
	created := op("createTenant", http.MethodPost, "/tenants", "Create a tenant with its roles and its owner")
	created.DefaultStatus = http.StatusCreated
	httpx.Register(api, created, w.createTenant, rbac.Requires(PermTenantsManage), write)
	httpx.Register(api, op("suspendTenant", http.MethodPost, "/tenants/{tenantId}/suspend", "Suspend a tenant; its sessions end"),
		w.suspendTenant, rbac.Requires(PermTenantsSuspend), write)
	httpx.Register(api, op("resumeTenant", http.MethodPost, "/tenants/{tenantId}/resume", "Make a tenant active again"),
		w.resumeTenant, rbac.Requires(PermTenantsSuspend), write)
	httpx.Register(api, op("listTenantAudit", http.MethodGet, "/tenants/{tenantId}/audit", "A tenant's audit trail, newest first"),
		w.tenantAudit, rbac.Requires(PermTenantsRead), read)
}

func (w *wiring) listTenants(ctx context.Context, in *listTenantsInput) (*httpx.List[tenancy.Tenant], error) {
	var list []tenancy.Tenant
	err := w.operatorTx(ctx, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		list, err = tenancy.List(ctx, tx, in.Cursor, in.Limit+1)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	page := paging.Page[tenancy.Tenant]{Items: list}
	if page.Items == nil {
		page.Items = []tenancy.Tenant{}
	}
	if len(list) > in.Limit {
		page.Items = list[:in.Limit]
		page.Next = page.Items[in.Limit-1].Slug
	}
	self := &url.URL{Path: BasePath + "/tenants", RawQuery: url.Values{"limit": {strconv.Itoa(in.Limit)}}.Encode()}
	return page.List(in.Limit, self), nil
}

func (w *wiring) createTenant(ctx context.Context, in *createTenantInput) (*httpx.One[tenancy.Tenant], error) {
	var out tenancy.Tenant
	err := w.operatorTx(ctx, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		owner, err := users.ByEmail(ctx, tx, in.Body.OwnerEmail)
		if errors.Is(err, users.ErrNotFound) {
			return problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, "no user has the owner's email; create them first")
		}
		if err != nil {
			return err
		}
		out, err = w.tenancy.Create(ctx, tx, tenancy.NewTenant{Slug: in.Body.Slug, Name: in.Body.Name, Owner: owner.ID, Domains: in.Body.Domains})
		return err
	})
	return one(out, err)
}

func (w *wiring) suspendTenant(ctx context.Context, in *tenantStateInput) (*httpx.One[tenancy.Tenant], error) {
	return w.setTenantState(ctx, in.TenantID, tenancy.Suspended, in.Body.Reason)
}

func (w *wiring) resumeTenant(ctx context.Context, in *tenantStateInput) (*httpx.One[tenancy.Tenant], error) {
	return w.setTenantState(ctx, in.TenantID, tenancy.Active, in.Body.Reason)
}

func (w *wiring) setTenantState(ctx context.Context, raw string, status tenancy.Status, reason string) (*httpx.One[tenancy.Tenant], error) {
	id, err := tenancy.ParseID(raw)
	if err != nil {
		return nil, tenancy.ErrNotFound
	}
	var out tenancy.Tenant
	err = w.operatorTx(ctx, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		out, err = w.tenancy.SetState(ctx, tx, id, status, reason)
		return err
	})
	return one(out, err)
}

func (w *wiring) tenantAudit(ctx context.Context, in *tenantAuditInput) (*httpx.List[audit.Entry], error) {
	id, err := tenancy.ParseID(in.TenantID)
	if err != nil {
		return nil, tenancy.ErrNotFound
	}
	var out []audit.Entry
	err = w.operatorTx(db.WithTenant(ctx, id.UUID()), func(ctx context.Context, tx db.Tx[db.Operator]) error {
		if _, err := tenancy.Get(ctx, tx, id); err != nil {
			return err
		}
		var err error
		out, err = audit.List(ctx, tx, in.Before, in.Limit)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []audit.Entry{}
	}
	var links httpx.Links
	if len(out) == in.Limit {
		next := (&url.URL{Path: BasePath + "/tenants/" + id.String() + "/audit", RawQuery: url.Values{
			"limit": {strconv.Itoa(in.Limit)}, "before": {strconv.FormatInt(out[len(out)-1].Seq, 10)},
		}.Encode()}).String()
		links.Next = &next
	}
	return httpx.ListOf(out, httpx.ListMeta{Limit: in.Limit}, links), nil
}

// inTenant puts the tenant a command names (--tenant slug) in ctx. Without the tenancy part the flag
// must be empty; with it, commands on tenant data need it.
func inTenant(ctx context.Context, deps Deps, slug string) (context.Context, error) {
	slug = strings.TrimSpace(slug)
	if !deps.Tenancy {
		if slug != "" {
			return nil, errors.New("--tenant needs the tenancy part (Postgres)")
		}
		return ctx, nil
	}
	if slug == "" {
		return nil, errors.New("--tenant is required: name the tenant by its slug (tenant:list)")
	}
	if err := tenancy.Install(deps.DB); err != nil {
		return nil, err
	}
	var t tenancy.Tenant
	err := db.InTx(ctx, deps.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		t, err = tenancy.BySlug(ctx, tx, slug)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	return tenancy.WithTenant(ctx, t), nil
}

func tenancyMapper(err error) (*problem.Problem, bool) { return tenancy.Mapper(err) }

func tenantFlag(fs *flag.FlagSet) {
	fs.String("tenant", "", "the tenant's slug (tenancy)")
}

func tenantCreateFlags(fs *flag.FlagSet) {
	fs.String("name", "", "the tenant's name")
	fs.String("owner", "", "email of an existing user who becomes its owner")
	fs.String("domains", "", "comma separated custom domains")
}

func tenantReasonFlags(fs *flag.FlagSet) {
	fs.String("reason", "", "why, for the audit log")
}

// tenantCommand opens the database with the operator pool for a tenant:* command.
func tenantCommand(ctx context.Context, environ []string) (Config, Deps, error) {
	cfg, err := LoadConfig(environ)
	if err != nil {
		return Config{}, Deps{}, errors.New("invalid configuration:\n" + err.Error())
	}
	deps, err := OpenDatabase(ctx, cfg)
	if err != nil {
		return Config{}, Deps{}, err
	}
	if !deps.Tenancy {
		_ = deps.DB.Close()
		return Config{}, Deps{}, errors.New("tenant commands need the tenancy part (Postgres)")
	}
	return cfg, deps, nil
}

// tenantCreate makes a tenant as the system: the slug is the first argument.
func tenantCreate(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		if len(args) != 1 || flagValue(fs, "owner") == "" {
			return cli.Usagef("tenant:create needs a slug and --owner")
		}
		cfg, deps, err := tenantCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		in := tenancy.NewTenant{Slug: args[0], Name: flagValue(fs, "name")}
		if in.Name == "" {
			in.Name = args[0]
		}
		if d := flagValue(fs, "domains"); d != "" {
			in.Domains = strings.Split(d, ",")
		}
		t, err := CreateTenant(ctx, cfg, deps, in, flagValue(fs, "owner"))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "created %s (%s)\n", t.Slug, t.ID)
		return err
	}
}

// CreateTenant makes a tenant as the system, owned by the existing user with ownerEmail.
func CreateTenant(ctx context.Context, cfg Config, deps Deps, in tenancy.NewTenant, ownerEmail string) (tenancy.Tenant, error) {
	w, err := newWiring(cfg, deps)
	if err != nil {
		return tenancy.Tenant{}, err
	}
	var t tenancy.Tenant
	err = w.operatorTx(ctx, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		owner, err := users.ByEmail(ctx, tx, ownerEmail)
		if err != nil {
			return err
		}
		in.Owner = owner.ID
		t, err = w.tenancy.Create(ctx, tx, in)
		return err
	})
	return t, err
}

// SetTenantState moves the tenant with slug to status as the system.
func SetTenantState(ctx context.Context, cfg Config, deps Deps, slug string, status tenancy.Status, reason string) (tenancy.Tenant, error) {
	w, err := newWiring(cfg, deps)
	if err != nil {
		return tenancy.Tenant{}, err
	}
	var t tenancy.Tenant
	err = w.operatorTx(ctx, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		found, err := tenancy.BySlug(ctx, tx, slug)
		if err != nil {
			return err
		}
		t, err = w.tenancy.SetState(ctx, tx, found.ID, status, reason)
		return err
	})
	return t, err
}

func tenantList(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		_, deps, err := tenantCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		table := cli.Table{Columns: []string{"id", "slug", "name", "status", "reason", "created_at"}}
		after := ""
		for {
			var page []tenancy.Tenant
			if err := db.InOperatorTx(ctx, deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
				var err error
				page, err = tenancy.List(ctx, tx, after, 500)
				return err
			}, db.ReadOnly()); err != nil {
				return err
			}
			for _, t := range page {
				table.Rows = append(table.Rows, []string{t.ID.String(), t.Slug, t.Name, string(t.Status), t.StatusReason, stamp(&t.CreatedAt)})
			}
			if len(page) < 500 {
				break
			}
			after = page[len(page)-1].Slug
		}
		return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
	}
}

// tenantSetState suspends or resumes the tenant whose slug is the first argument, as the system.
func tenantSetState(environ []string, status tenancy.Status) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		if len(args) != 1 {
			return cli.Usagef("name one tenant by its slug")
		}
		cfg, deps, err := tenantCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		t, err := SetTenantState(ctx, cfg, deps, args[0], status, flagValue(fs, "reason"))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "%s is %s\n", t.Slug, t.Status)
		return err
	}
}

// setupOperator makes the operator realm's missing built-in roles on the operator pool (rows without a
// tenant, which the app role may read but not write) and syncs the existing built-in roles, the
// operator realm's and each tenant's copies, with their definitions.
func setupOperator(ctx context.Context, deps Deps, access *rbac.Access) (SetupResult, error) {
	var out SetupResult
	err := db.InOperatorTx(ctx, deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		if out.Created, err = access.Setup(ctx, tx, RealmOperator, operatorBuiltins); err != nil {
			return err
		}
		out.Synced, err = access.Sync(ctx, tx, RealmOperator, operatorBuiltins)
		return err
	})
	if err != nil {
		return SetupResult{}, err
	}
	tenants, err := syncTenantRoles(ctx, deps, access)
	out.Synced = append(out.Synced, tenants...)
	return out, err
}

// grantOperator gives an operator role as the system, on the operator pool.
func grantOperator(ctx context.Context, deps Deps, access *rbac.Access, code, email string) error {
	return db.InOperatorTx(ctx, deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		u, err := users.ByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		role, err := rbac.RoleByCode(ctx, tx, RealmOperator, code)
		if err != nil {
			return err
		}
		return access.Grant(ctx, tx, rbac.System(RealmOperator), rbac.UserRole{UserID: u.ID, RoleID: role.ID})
	})
}

// joinTenant makes the user with email a member of the context's tenant, when there is one (a grant
// from a command), on the operator pool, which alone writes memberships.
func joinTenant(ctx context.Context, deps Deps, email string) error {
	t, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil
	}
	return db.InOperatorTx(ctx, deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		u, err := users.ByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		return tenancy.AddMember(ctx, tx, t.ID, u.ID)
	})
}

// tenancyCommands are the tenant:* commands.
func tenancyCommands(environ []string) []cli.Command {
	return []cli.Command{
		{Name: "tenant:create", Summary: "Create a tenant with its roles and its owner", Flags: tenantCreateFlags, Run: tenantCreate(environ)},
		{Name: "tenant:list", Summary: "List tenants and their state", Flags: cli.JSONFlag, Run: tenantList(environ)},
		{Name: "tenant:suspend", Summary: "Suspend a tenant: every request refused, its sessions ended", Flags: tenantReasonFlags, Run: tenantSetState(environ, tenancy.Suspended)},
		{Name: "tenant:resume", Summary: "Make a suspended or read-only tenant active again", Flags: tenantReasonFlags, Run: tenantSetState(environ, tenancy.Active)},
	}
}

// queueTx runs the queue's bookkeeping: under tenancy on the operator pool, where one place claims,
// reaps and prunes the jobs of every tenant.
func queueTx(deps Deps) jobs.TxRunner {
	if deps.Tenancy {
		return jobs.OperatorTx(deps.Operator)
	}
	return jobs.PlainTx(deps.DB)
}

// maintenanceTx runs global maintenance (prunes, sweeps): under tenancy on the operator pool, so one run
// covers every tenant.
func maintenanceTx(deps Deps) jobs.TxRunner {
	if deps.Tenancy {
		return jobs.TxRunner(tenancy.OperatorRunner(deps.Operator))
	}
	return jobs.PlainTx(deps.DB)
}

// jobTx is for kit services whose own transactions run only in jobs and shell commands (mail, outbound
// webhooks): a job of a tenant gets that tenant's transaction; a global kind or a command, the operator
// pool. Never hand it to work a request starts.
//
//nolint:unused // called by the mail and webhooks parts; an app without both never calls it
func jobTx(deps Deps) jobs.TxRunner {
	if !deps.Tenancy {
		return jobs.PlainTx(deps.DB)
	}
	tenant, global := tenancy.Runner(deps.DB), tenancy.OperatorRunner(deps.Operator)
	return func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
		if _, ok := db.TenantOf(ctx); ok {
			return tenant(ctx, fn)
		}
		return global(ctx, fn)
	}
}

// eachTenant runs fn once per tenant with the tenant in its context (suspended ones only with
// suspended), or once without tenancy. fn usually enqueues a job, which then runs as that tenant.
func eachTenant(ctx context.Context, deps Deps, suspended bool, fn func(ctx context.Context) error) error {
	if !deps.Tenancy {
		return fn(ctx)
	}
	after := ""
	for {
		var page []tenancy.Tenant
		if err := db.InOperatorTx(ctx, deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
			var err error
			page, err = tenancy.List(ctx, tx, after, 500)
			return err
		}, db.ReadOnly()); err != nil {
			return err
		}
		for _, t := range page {
			if t.Status == tenancy.Suspended && !suspended {
				continue
			}
			if err := fn(db.WithTenant(ctx, t.ID.UUID())); err != nil {
				return err
			}
		}
		if len(page) < 500 {
			return nil
		}
		after = page[len(page)-1].Slug
	}
}

// syncTenantRoles brings each tenant's copies of the built-in roles in step with their templates, one
// tenant transaction each; suspended tenants' roles change with the app too.
func syncTenantRoles(ctx context.Context, deps Deps, access *rbac.Access) ([]rbac.Role, error) {
	var changed []rbac.Role
	err := eachTenant(ctx, deps, true, func(ctx context.Context) error {
		return db.InTx(ctx, deps.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
			roles, err := access.Sync(ctx, tx, RealmTenant, builtinRoles[RealmTenant])
			changed = append(changed, roles...)
			return err
		})
	})
	return changed, err
}

// seedTenancy gives the seeded administrator a tenant with slug they own and the operator role.
func seedTenancy(ctx context.Context, cfg Config, deps Deps, rec *audit.Recorder, email, slug string) error {
	_, err := CreateTenant(ctx, cfg, deps, tenancy.NewTenant{Slug: slug, Name: slug}, email)
	if err != nil && !errors.Is(err, tenancy.ErrSlugTaken) {
		return err
	}
	return alreadyGranted(grantOperator(ctx, deps, NewAccess(rec), "operator", email))
}

// checkTenancy is doctor's view of the roles and the schema rules (tenancy.md sections 3 and 4).
func checkTenancy(ctx context.Context, deps Deps, behind bool) []Check {
	if !deps.Tenancy {
		return checkNoTenancy(ctx, deps.DB)
	}
	roles := bounded(ctx, func(ctx context.Context) Check {
		if deps.Operator == nil {
			return fail("roles", "the tenancy part needs APP_DATABASE_OPERATOR_URL")
		}
		if err := tenancy.CheckRoles(ctx, deps.DB, deps.Operator); err != nil {
			return fail("roles", err.Error())
		}
		return pass("roles", "the app role cannot bypass row-level security or own tables; the operator role can bypass it")
	})
	if behind {
		return []Check{roles, skip("row-level security", "needs the current schema: migrations are behind")}
	}
	rls := bounded(ctx, func(ctx context.Context) Check {
		if err := matchTenancySchema(ctx, deps.DB, true); err != nil {
			return fail("row-level security", err.Error())
		}
		if err := CheckSchema(ctx, deps.DB); err != nil {
			return fail("row-level security", strings.ReplaceAll(err.Error(), "\n", "; "))
		}
		return pass("row-level security", "every tenant table has it enabled, forced and a policy")
	})
	return []Check{roles, rls}
}
