package tenancy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
)

// Exception lets the catalogue check pass something the tenant rules would refuse; Reason is required,
// since it is what a reviewer reads. With only Table set it names a global table, shared by every
// tenant (no row-level security; its migration says -- keel:global). With Index or Policy it names one
// index of a tenant table that need not lead with tenant_id, or one policy beside the tenant policy.
// With Nullable it lets a tenant table hold rows without a tenant. Function names a security definer
// function by its schema-qualified signature with argument types (public.name(integer, text));
// BodySHA256 is the hex SHA-256 of its body (pg_proc.prosrc), so a changed body needs a new review.
type Exception struct {
	Table      string
	Index      string
	Policy     string
	Nullable   bool
	Function   string
	BodySHA256 string
	Reason     string
}

// Global is true for an exception that names a global table.
func (e Exception) Global() bool {
	return e.Table != "" && e.Index == "" && e.Policy == "" && !e.Nullable
}

// KitExceptions are the kit's own.
var KitExceptions = []Exception{
	{Table: "users", Reason: "one identity across tenants; memberships grant entry"},
	{Table: "credentials", Reason: "per user, like users"},
	{Table: "auth_tokens", Reason: "per user, like users"},
	{Table: "mfa_totp", Reason: "per user, like users"},
	{Table: "mfa_recovery_codes", Reason: "per user, like users"},
	{Table: "sessions", Reason: "a session belongs to a user and records its current tenant"},
	{Table: "passkeys", Reason: "per user, bound to the realm they were registered on"},
	{Table: "identities", Reason: "per user, bound to the realm they were linked on"},
	{Table: "auth_challenges", Reason: "sign-in challenges made before a tenant is known"},
	{Table: "oauth_states", Reason: "sign-in state made before a tenant is known; Take checks the recorded tenant"},
	{Table: "locks", Reason: "advisory lock names; db.Lock prefixes them with the tenant"},
	{Table: "rate_counters", Reason: "counters keyed by caller; ratelimit.ByTenant puts the tenant in the key"},
	{Table: "webhook_deliveries", Reason: "inbound delivery ids, recorded before any tenant is known"},
	{Table: "job_schedules", Reason: "schedules of global maintenance kinds"},
	{Table: "tenants", Reason: "the tenant list itself, read before a tenant is chosen; the app role only reads it"},
	{Table: "tenant_domains", Reason: "resolves a host before a tenant is chosen; the app role only reads it"},
	{Table: "memberships", Reason: "read at sign-in, before a tenant is chosen; the app role only reads it"},
	{Table: "audit_log", Nullable: true, Reason: "sign-in on a shared host and maintenance write rows without a tenant; only the operator role reads them"},
	{Table: "audit_chain", Nullable: true, Reason: "the global trail's head has no tenant; reachable only where no tenant is set"},
	{Table: "jobs", Nullable: true, Reason: "global kinds (maintenance, schedules, mail) run without a tenant"},
	{Table: "mail_outbox", Nullable: true, Reason: "mail sent where no tenant is set, such as a shared-host password reset"},
	{Table: "idempotency_keys", Nullable: true, Reason: "requests without a tenant keep keys too, scoped by realm and principal"},
	{Table: "roles", Nullable: true, Reason: "the operator realm's roles have no tenant"},
	{Table: "role_permissions", Nullable: true, Reason: "the operator realm's roles have no tenant"},
	{Table: "user_roles", Nullable: true, Reason: "the operator realm's grants have no tenant"},
	{Table: "jobs", Index: "jobs_ready", Reason: "workers claim the next job of every tenant on the operator pool"},
	{Table: "jobs", Index: "jobs_leased", Reason: "the reaper finds expired leases of every tenant on the operator pool"},
	{Table: "audit_log", Index: "audit_log_seq_key", Reason: "seq is a platform-wide identity; a trail shows its gaps (docs/tenancy.md section 4)"},
	{Table: "audit_chain", Index: "audit_chain_pkey", Reason: "the chain key is the tenant id itself; a check keeps them equal"},
	{Table: "api_key_tenants", Index: "api_key_tenants_pkey", Reason: "a presented key is located by its id before its tenant is known"},
	{Table: "api_key_tenants", Policy: "locate", Reason: "a presented key is located before its tenant is known; writes keep the tenant policy"},
	{Table: "roles", Policy: "global_read", Reason: "operator-realm roles have no tenant; readable only where no tenant is set"},
	{Table: "role_permissions", Policy: "global_read", Reason: "operator-realm roles have no tenant; readable only where no tenant is set"},
	{Table: "user_roles", Policy: "global_read", Reason: "operator-realm grants have no tenant; readable only where no tenant is set"},
	{
		Function: "public.keel_migrations_applied()", BodySHA256: "3a95de2e49691323ac94646f89779eb32c152367077f9e2011753d9a20b4d493",
		Reason: "reads the migration ledger only, with a pinned search_path",
	},
}

// KitProcedural are the kit's migrations that run procedural SQL under tenancy (migrate.Procedural).
var KitProcedural = []migrate.Procedural{
	{File: "20261022153800_kit_audit_log.sql", Reason: "revokes update, delete and truncate on audit_log from every grantee"},
	{File: "20261022155454_kit_migrations_applied.sql", Reason: "grants the ledger function to the app and operator roles where they exist"},
	{File: "20261022192140_tenancy_tenants.sql", Reason: "revokes writes on tenants from every role under row-level security"},
	{File: "20261022192141_tenancy_tenant_domains.sql", Reason: "revokes writes on tenant_domains from every role under row-level security"},
	{File: "20261022192143_tenancy_memberships.sql", Reason: "revokes writes on memberships from every role under row-level security"},
}

// The tenant policy's expressions as Postgres prints them back (pg_get_expr), normalised: a not-null
// tenant_id must equal the setting, and a nullable one may also match no tenant to no setting.
var (
	tenantEquals   = normaliseExpr(`(tenant_id = ( SELECT (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))`)
	tenantNullSafe = normaliseExpr(`(NOT (tenant_id IS DISTINCT FROM ( SELECT (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)))`)
	exprAlias      = regexp.MustCompile(`(?i)\s+as\s+"[^"]*"`)
	exprSpace      = regexp.MustCompile(`\s+`)
)

func normaliseExpr(s string) string {
	return strings.ToLower(exprSpace.ReplaceAllString(exprAlias.ReplaceAllString(s, ""), ""))
}

// CheckCatalogue reports every object in the public schema that breaks docs/tenancy.md section 4. Every
// table is a tenant table unless an exception names it global. A tenant table has tenant_id, row-level
// security enabled and forced, exactly the tenant policy (a permissive policy for all commands whose
// using and with check are the template's) plus excepted ones, tenant_id leading every index (a
// nullable tenant_id cannot be in a primary key, so such a table keeps one on id, made in Go), and
// tenant_id on both sides of every foreign key to a tenant table, itself included; its tenant_id is not
// null unless an exception says otherwise. A global table has no foreign key into a tenant table. Views
// run as their caller (security_invoker). A security definer function, in any schema, is excepted by its
// signature and body fingerprint, is owned by a role under row-level security, pins its search_path and
// is not executable by PUBLIC.
func CheckCatalogue(ctx context.Context, tx db.Transaction, extra ...Exception) error {
	allowed := append(append([]Exception(nil), KitExceptions...), extra...)
	for _, e := range allowed {
		if e.Reason == "" {
			return fmt.Errorf("tenancy: the exception for %s%s%s%s needs a reason", e.Table, e.Index, e.Policy, e.Function)
		}
		if e.Function != "" && e.BodySHA256 == "" {
			return fmt.Errorf("tenancy: the exception for function %s needs the SHA-256 of its body", e.Function)
		}
	}
	tables, err := catalogue(ctx, tx)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		t := tables[name]
		switch {
		case isGlobal(allowed, name):
			errs = append(errs, globalForeignKeys(allowed, tables, name, t)...)
		case t.view:
			if !t.invoker {
				errs = append(errs, fmt.Errorf("%s: a view must be created with (security_invoker = true), so row-level security applies to its reader", name))
			}
		case !t.tenant:
			errs = append(errs, fmt.Errorf("%s: has no tenant_id; give it one under row-level security, or except it as a global table with a reason", name))
		default:
			errs = append(errs, checkTenantTable(allowed, tables, name, t)...)
		}
	}
	definers, err := definerFunctions(ctx, tx)
	if err != nil {
		return err
	}
	for _, fn := range definers {
		errs = append(errs, checkDefiner(allowed, fn)...)
	}
	return errors.Join(errs...)
}

func checkDefiner(allowed []Exception, fn definerFacts) []error {
	i := slices.IndexFunc(allowed, func(e Exception) bool { return e.Function == fn.signature })
	if i < 0 {
		return []error{fmt.Errorf("function %s: security definer skips row-level security; except it by signature, with its body's SHA-256 and a reason, after review", fn.signature)}
	}
	var errs []error
	if fn.privilegedOwner {
		errs = append(errs, fmt.Errorf("function %s: owned by %s, which is a superuser or bypasses row-level security; let the owner role create it", fn.signature, fn.owner))
	}
	if !fn.pinned {
		errs = append(errs, fmt.Errorf("function %s: a security definer function must pin its search_path (set search_path = pg_catalog, pg_temp)", fn.signature))
	}
	if fn.publicExecute {
		errs = append(errs, fmt.Errorf("function %s: PUBLIC may execute it; revoke execute from public and grant it to the roles that call it", fn.signature))
	}
	if fn.bodySHA256 != allowed[i].BodySHA256 {
		errs = append(errs, fmt.Errorf("function %s: its body's SHA-256 is %s, not the %s its exception names; review the body, then update the exception",
			fn.signature, fn.bodySHA256, allowed[i].BodySHA256))
	}
	return errs
}

func checkTenantTable(allowed []Exception, tables map[string]*tableFacts, name string, t *tableFacts) []error {
	var errs []error
	if t.nullable && !slices.ContainsFunc(allowed, func(e Exception) bool { return e.Table == name && e.Nullable }) {
		errs = append(errs, fmt.Errorf("%s: tenant_id must be not null; a table that holds rows without a tenant needs an exception with Nullable and a reason", name))
	}
	if !t.rls || !t.forced {
		errs = append(errs, fmt.Errorf("%s: row-level security must be enabled and forced", name))
	}
	tenantPolicy := false
	for _, p := range t.policies {
		switch {
		case p.isTenantPolicy(t.nullable):
			tenantPolicy = true
		case !slices.ContainsFunc(allowed, func(e Exception) bool { return e.Table == name && e.Policy == p.name }):
			errs = append(errs, fmt.Errorf("%s: policy %s is not the tenant policy; drop it or except it with a reason", name, p.name))
		}
	}
	if !tenantPolicy {
		errs = append(errs, fmt.Errorf("%s: needs the tenant policy: for all commands, using and with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))", name))
	}
	for _, ix := range t.indexes {
		switch {
		case ix.leading == "tenant_id", slices.ContainsFunc(allowed, func(e Exception) bool { return e.Table == name && e.Index == ix.name }):
		case ix.primary && t.nullable && ix.columns == "id":
		default:
			errs = append(errs, fmt.Errorf("%s: index %s must lead with tenant_id", name, ix.name))
		}
	}
	for _, fk := range t.foreign {
		if target := tables[fk.target]; target == nil || !target.tenant || isGlobal(allowed, fk.target) {
			continue
		}
		if !fk.tenantPaired {
			errs = append(errs, fmt.Errorf("%s: foreign key %s to %s must include tenant_id on both sides", name, fk.name, fk.target))
		}
	}
	return errs
}

func globalForeignKeys(allowed []Exception, tables map[string]*tableFacts, name string, t *tableFacts) []error {
	var errs []error
	for _, fk := range t.foreign {
		if target := tables[fk.target]; target != nil && target.tenant && !target.view && !isGlobal(allowed, fk.target) {
			errs = append(errs, fmt.Errorf("%s: a global table's foreign key %s points into tenant table %s", name, fk.name, fk.target))
		}
	}
	return errs
}

// AllowedPolicies are the policies besides the tenant policy that the kit's exceptions and extra name,
// for migrate.Validate.
func AllowedPolicies(extra ...Exception) []migrate.Policy {
	var out []migrate.Policy
	for _, e := range append(append([]Exception(nil), KitExceptions...), extra...) {
		if e.Policy != "" {
			out = append(out, migrate.Policy{Table: e.Table, Name: e.Policy, Reason: e.Reason})
		}
	}
	return out
}

func isGlobal(list []Exception, table string) bool {
	return slices.ContainsFunc(list, func(e Exception) bool { return e.Global() && e.Table == table })
}

type tableFacts struct {
	view, invoker                 bool
	tenant, nullable, rls, forced bool
	policies                      []policyFacts
	indexes                       []indexFacts
	foreign                       []foreignFacts
}

type policyFacts struct {
	name, cmd, using, check string
	permissive              bool
}

func (p policyFacts) isTenantPolicy(nullable bool) bool {
	ok := func(expr string) bool { return expr == tenantEquals || (nullable && expr == tenantNullSafe) }
	return p.permissive && p.cmd == "ALL" && ok(normaliseExpr(p.using)) && ok(normaliseExpr(p.check))
}

type indexFacts struct {
	name, leading, columns string
	primary                bool
}

type foreignFacts struct {
	name, target string
	tenantPaired bool
}

func catalogue(ctx context.Context, tx db.Transaction) (map[string]*tableFacts, error) {
	out := map[string]*tableFacts{}
	rows, err := tx.Q().QueryContext(ctx, `SELECT c.relname, c.relkind IN ('v', 'm'),
		coalesce(c.reloptions && ARRAY['security_invoker=true', 'security_invoker=on', 'security_invoker=1'], false),
		a.attname IS NOT NULL, coalesce(NOT a.attnotnull, false), c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm')`)
	if err != nil {
		return nil, fmt.Errorf("tenancy catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		t := &tableFacts{}
		if err := rows.Scan(&name, &t.view, &t.invoker, &t.tenant, &t.nullable, &t.rls, &t.forced); err != nil {
			return nil, err
		}
		out[name] = t
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	if err := policies(ctx, tx, out); err != nil {
		return nil, err
	}
	if err := indexes(ctx, tx, out); err != nil {
		return nil, err
	}
	return out, foreignKeys(ctx, tx, out)
}

func policies(ctx context.Context, tx db.Transaction, tables map[string]*tableFacts) error {
	rows, err := tx.Q().QueryContext(ctx, `SELECT tablename, policyname, cmd, permissive = 'PERMISSIVE', coalesce(qual, ''), coalesce(with_check, '')
		FROM pg_policies WHERE schemaname = 'public'`)
	if err != nil {
		return fmt.Errorf("tenancy catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var table string
		var p policyFacts
		if err := rows.Scan(&table, &p.name, &p.cmd, &p.permissive, &p.using, &p.check); err != nil {
			return err
		}
		if t := tables[table]; t != nil {
			t.policies = append(t.policies, p)
		}
	}
	return rows.Err()
}

func indexes(ctx context.Context, tx db.Transaction, tables map[string]*tableFacts) error {
	rows, err := tx.Q().QueryContext(ctx, `SELECT t.relname, i.relname, x.indisprimary,
		coalesce((SELECT attname FROM pg_attribute WHERE attrelid = t.oid AND attnum = x.indkey[0]), ''),
		coalesce((SELECT string_agg(a.attname, ',' ORDER BY k.ord) FROM unnest(x.indkey::int2[]) WITH ORDINALITY k(attnum, ord)
			JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum), '')
		FROM pg_index x JOIN pg_class t ON t.oid = x.indrelid JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = 'public'`)
	if err != nil {
		return fmt.Errorf("tenancy catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var table string
		var ix indexFacts
		if err := rows.Scan(&table, &ix.name, &ix.primary, &ix.leading, &ix.columns); err != nil {
			return err
		}
		if t := tables[table]; t != nil {
			t.indexes = append(t.indexes, ix)
		}
	}
	return rows.Err()
}

func foreignKeys(ctx context.Context, tx db.Transaction, tables map[string]*tableFacts) error {
	rows, err := tx.Q().QueryContext(ctx, `SELECT t.relname, c.conname, f.relname,
		EXISTS (SELECT 1 FROM unnest(c.conkey, c.confkey) k(own, other)
			JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.own
			JOIN pg_attribute b ON b.attrelid = c.confrelid AND b.attnum = k.other
			WHERE a.attname = 'tenant_id' AND b.attname = 'tenant_id')
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_class f ON f.oid = c.confrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace WHERE c.contype = 'f' AND n.nspname = 'public'`)
	if err != nil {
		return fmt.Errorf("tenancy catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var table string
		var fk foreignFacts
		if err := rows.Scan(&table, &fk.name, &fk.target, &fk.tenantPaired); err != nil {
			return err
		}
		if t := tables[table]; t != nil {
			t.foreign = append(t.foreign, fk)
		}
	}
	return rows.Err()
}

type definerFacts struct {
	signature, owner, bodySHA256           string
	privilegedOwner, pinned, publicExecute bool
}

// definerFunctions reads every security definer function outside the system schemas. The signature is
// built by hand: regprocedure leaves out a schema that is on the search path.
func definerFunctions(ctx context.Context, tx db.Transaction) ([]definerFacts, error) {
	rows, err := tx.Q().QueryContext(ctx, `SELECT quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' ||
			coalesce((SELECT string_agg(format_type(a.t, NULL), ', ' ORDER BY a.i) FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY a(t, i)), '') || ')',
		r.rolname, r.rolsuper OR r.rolbypassrls, p.prosrc,
		coalesce(EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search\_path=%'), false),
		EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
		WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("tenancy catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []definerFacts
	for rows.Next() {
		var f definerFacts
		var body string
		if err := rows.Scan(&f.signature, &f.owner, &f.privilegedOwner, &body, &f.pinned, &f.publicExecute); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(body))
		f.bodySHA256 = hex.EncodeToString(sum[:])
		out = append(out, f)
	}
	return out, rows.Err()
}

// CheckRoles refuses to serve when the app pool's role could step around row-level security: it is,
// or is a member of, a superuser, a role with bypassrls, a role owning tables in public (which may turn
// it off) or the operator role; it may write the tenant control tables; a view in public is owned by a
// role that bypasses row-level security; or the database or a role sets a default for an app.*
// setting or the search path. It also refuses a missing operator pool, an operator login without
// bypassrls of its own, one that is or belongs to a superuser or a role that may create roles or
// databases or replicate, both pools on one role, and a pool that acts as another role than the one its
// URL logs in as (RESET ROLE would return to the login, which these checks never saw).
func CheckRoles(ctx context.Context, d *db.DB, operator *db.OperatorAccess) error {
	var op roleFacts
	var opProblems []string
	if err := db.InOperatorTx(ctx, operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		if op, err = currentRole(ctx, tx); err != nil {
			return err
		}
		opProblems, err = queryStrings(ctx, tx, operatorMemberships)
		return err
	}, db.ReadOnly()); err != nil {
		return fmt.Errorf("tenancy needs the operator pool (DATABASE_OPERATOR_URL): %w", err)
	}
	var app roleFacts
	var problems []string
	err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		if app, err = currentRole(ctx, tx); err != nil {
			return err
		}
		problems, err = queryStrings(ctx, tx, roleProblems, op.name)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	var errs []error
	errs = append(errs, actsAsLogin("app", app, d.LoginRole()), actsAsLogin("operator", op, operator.LoginRole()))
	if app.super || app.bypass {
		errs = append(errs, fmt.Errorf("the app pool's role %s is a superuser or bypasses row-level security", app.name))
	}
	if app.owns > 0 {
		errs = append(errs, fmt.Errorf("the app pool's role %s owns %d tables; migrations run as the owner role (DATABASE_MIGRATE_URL)", app.name, app.owns))
	}
	if !op.bypass {
		errs = append(errs, fmt.Errorf("the operator pool's role %s does not bypass row-level security (bypassrls is not inherited: give it to the login)", op.name))
	}
	for _, a := range []struct {
		held bool
		what string
	}{{op.super, "is a superuser"}, {op.createRole, "may create roles"}, {op.createDB, "may create databases"}, {op.replication, "may replicate"}} {
		if a.held {
			errs = append(errs, fmt.Errorf("the operator pool's role %s %s; it needs bypassrls and nothing more", op.name, a.what))
		}
	}
	for _, p := range opProblems {
		errs = append(errs, errors.New(p))
	}
	if op.name == app.name {
		errs = append(errs, errors.New("the operator pool must use another role than the app pool"))
	}
	for _, p := range problems {
		errs = append(errs, errors.New(p))
	}
	return errors.Join(errs...)
}

// roleProblems lists, as sentences, what lets the app pool's role (current_user) around row-level
// security beyond its own attributes; $1 is the operator role.
const roleProblems = `SELECT format('the app pool''s role is a member of %s, which %s', r.rolname,
		CASE WHEN r.rolname = $1 THEN 'is the operator role' WHEN r.rolsuper THEN 'is a superuser'
			WHEN r.rolbypassrls THEN 'bypasses row-level security' ELSE 'owns tables in public' END)
	FROM pg_roles r WHERE r.rolname <> current_user AND pg_has_role(current_user, r.oid, 'MEMBER')
		AND (r.rolname = $1 OR r.rolsuper OR r.rolbypassrls
			OR EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tableowner = r.rolname))
	UNION ALL
	SELECT format('the app pool''s role may write %s; only the operator pool writes it', t)
	FROM unnest(ARRAY['tenants', 'tenant_domains', 'memberships']) t
	WHERE to_regclass('public.' || t) IS NOT NULL AND has_table_privilege(current_user, 'public.' || t, 'INSERT, UPDATE, DELETE, TRUNCATE')
	UNION ALL
	SELECT format('view %s is owned by %s, which bypasses row-level security', c.relname, r.rolname)
	FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
	WHERE n.nspname = 'public' AND c.relkind IN ('v', 'm') AND (r.rolsuper OR r.rolbypassrls)
	UNION ALL
	SELECT format('%s sets a default for %s; %s', CASE WHEN s.setrole = 0 THEN 'the database' ELSE 'role ' || s.setrole::regrole::text END,
		split_part(c, '=', 1), CASE WHEN c LIKE 'app.%' THEN 'nothing may preset the tenant setting' ELSE 'unqualified names must resolve in public' END)
	FROM pg_db_role_setting s, unnest(s.setconfig) c
	WHERE (c LIKE 'app.%' OR lower(c) LIKE 'search\_path=%') AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
		AND (s.setrole = 0 OR s.setrole = (SELECT oid FROM pg_roles WHERE rolname = $1) OR pg_has_role(current_user, s.setrole, 'MEMBER'))`

// operatorMemberships lists, as sentences, the roles the operator pool's role (current_user) belongs to
// that hold more than it may.
const operatorMemberships = `SELECT format('the operator pool''s role is a member of %s, which %s', r.rolname,
		CASE WHEN r.rolsuper THEN 'is a superuser' WHEN r.rolcreaterole THEN 'may create roles'
			WHEN r.rolcreatedb THEN 'may create databases' ELSE 'may replicate' END)
	FROM pg_roles r WHERE r.rolname <> current_user AND pg_has_role(current_user, r.oid, 'MEMBER')
		AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)`

func queryStrings(ctx context.Context, tx db.Transaction, query string, args ...any) ([]string, error) {
	rows, err := tx.Q().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("check database roles: %w", err)
	}
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

type roleFacts struct {
	name, session                     string
	super, bypass                     bool
	createRole, createDB, replication bool
	owns                              int
}

func actsAsLogin(pool string, f roleFacts, login string) error {
	switch {
	case login == "":
		return fmt.Errorf("the %s pool's login role is unknown: open the database with db.Open", pool)
	case f.session != login || f.name != login:
		return fmt.Errorf("the %s pool logs in as %s and acts as %s, but its URL names %s: log in as the role the pool acts as, with no role switch",
			pool, f.session, f.name, login)
	}
	return nil
}

func currentRole(ctx context.Context, tx db.Transaction) (roleFacts, error) {
	rows, err := tx.Q().QueryContext(ctx, `SELECT r.rolname, session_user, r.rolsuper, r.rolbypassrls,
		r.rolcreaterole, r.rolcreatedb, r.rolreplication, (SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user)
		FROM pg_roles r WHERE r.rolname = current_user`)
	if err != nil {
		return roleFacts{}, fmt.Errorf("check database role: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var f roleFacts
	for rows.Next() {
		if err := rows.Scan(&f.name, &f.session, &f.super, &f.bypass, &f.createRole, &f.createDB, &f.replication, &f.owns); err != nil {
			return roleFacts{}, err
		}
	}
	return f, rows.Err()
}
