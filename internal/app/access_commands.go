package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func routeList(_ context.Context, fs *flag.FlagSet, _ []string) error {
	set, err := Operations()
	if err != nil {
		return err
	}
	table := cli.Table{Columns: []string{"method", "path", "realm", "need", "rate_class"}}
	set.Each(func(r realm.Realm, api huma.API) {
		for _, op := range httpx.Operations(api) {
			need := "none"
			if n, ok := rbac.NeedOf(op); ok {
				need = n.String()
			}
			class, _ := ratelimit.ClassOf(op)
			table.Rows = append(table.Rows, []string{op.Method, op.Path, r.Name, need, class})
		}
	})
	return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
}

func permissionList(_ context.Context, fs *flag.FlagSet, _ []string) error {
	table := cli.Table{Columns: []string{"realm", "code", "area", "label", "sensitive", "api_grantable", "builtin_roles"}}
	for _, r := range realms() {
		for _, p := range r.Catalogue.All() {
			var holders []string
			for _, b := range builtinRoles[r.Name] {
				if slices.Contains(b.Permissions, p.Code) {
					holders = append(holders, b.Code)
				}
			}
			table.Rows = append(table.Rows, []string{
				r.Name, string(p.Code), p.Area, p.Label,
				strconv.FormatBool(p.Sensitive), strconv.FormatBool(p.APIGrantable), strings.Join(holders, ","),
			})
		}
	}
	return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
}

func setup(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		cfg, err := LoadConfig(environ)
		if err != nil {
			return errors.New("invalid configuration:\n" + err.Error())
		}
		deps, err := OpenDatabase(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		res, err := Setup(ctx, deps, audit.New(audit.Options{Chain: cfg.Audit.Chain}))
		if err != nil {
			return err
		}
		table := cli.Table{Columns: []string{"realm", "role", "change"}}
		for _, r := range res.Created {
			table.Rows = append(table.Rows, []string{r.Realm, r.Code, "created"})
		}
		for _, r := range res.Synced {
			table.Rows = append(table.Rows, []string{r.Realm, r.Code, "permissions synced"})
		}
		return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
	}
}

// SetupResult is what Setup changed: built-in roles it created, and existing ones whose permissions it
// brought in step with their definitions.
type SetupResult struct {
	Created []rbac.Role
	Synced  []rbac.Role
}

// Setup creates every realm's missing built-in roles and brings the existing ones' permissions in step
// with their definitions (audited, so a new module's permissions reach a database set up before it); it
// is safe to run on every deploy. Without tenancy it is one transaction. Under tenancy the tenant realm's
// built-in roles are templates copied into each new tenant, so Setup makes only the operator realm's in
// one operator transaction, then syncs each tenant's copies in a transaction per tenant: a failure part
// way leaves the tenants done so far synced, and a rerun finishes the rest.
func Setup(ctx context.Context, deps Deps, rec *audit.Recorder) (SetupResult, error) {
	access := NewAccess(rec)
	if deps.Tenancy {
		return setupOperator(ctx, deps, access)
	}
	var out SetupResult
	err := db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
		out = SetupResult{}
		for _, r := range realms() {
			created, err := access.Setup(ctx, tx, r.Name, builtinRoles[r.Name])
			if err != nil {
				return err
			}
			synced, err := access.Sync(ctx, tx, r.Name, builtinRoles[r.Name])
			if err != nil {
				return err
			}
			out.Created, out.Synced = append(out.Created, created...), append(out.Synced, synced...)
		}
		return nil
	})
	return out, err
}

func userGrantFlags(fs *flag.FlagSet) {
	fs.String("realm", RealmTenant, "realm of the role")
	fs.String("role", "", "role code, such as admin")
	tenantFlag(fs)
}

// userGrant is break-glass: it grants as the system, which skips the checks of what the actor holds
// but not the realm check, and is audited as the system.
func userGrant(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		realmName, role := fs.Lookup("realm").Value.String(), fs.Lookup("role").Value.String()
		if len(args) != 1 || role == "" {
			return cli.Usagef("user:grant needs --role and one email address")
		}
		cfg, err := LoadConfig(environ)
		if err != nil {
			return errors.New("invalid configuration:\n" + err.Error())
		}
		deps, err := OpenDatabase(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		if err := GrantRole(ctx, deps, audit.New(audit.Options{Chain: cfg.Audit.Chain}), realmName, role, args[0], flagValue(fs, "tenant")); err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "granted %s in %s\n", role, realmName)
		return err
	}
}

// GrantRole gives the user with email the role code of realm, as the system. Under tenancy a tenant
// realm role is the named tenant's (the user joins it first, on the operator pool, which alone writes
// memberships), and operator roles are granted on the operator pool.
func GrantRole(ctx context.Context, deps Deps, rec *audit.Recorder, realmName, code, email, tenant string) error {
	access := NewAccess(rec)
	if deps.Tenancy && realmName == RealmOperator {
		return grantOperator(ctx, deps, access, code, email)
	}
	ctx, err := inTenant(ctx, deps, tenant)
	if err != nil {
		return err
	}
	if err := joinTenant(ctx, deps, email); err != nil {
		return err
	}
	return db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.ByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		role, err := rbac.RoleByCode(ctx, tx, realmName, code)
		if err != nil {
			return err
		}
		return access.Grant(ctx, tx, rbac.System(realmName), rbac.UserRole{UserID: u.ID, RoleID: role.ID})
	})
}

func userCreateFlags(fs *flag.FlagSet) {
	fs.String("name", "", "display name")
	fs.Bool("print-link", false, "print the invite token here instead of sending it (no notifier needed)")
}

// userCreate creates a user as the system and hands the invite to the notifier, or prints it to the
// operator's own terminal with --print-link.
func userCreate(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		if len(args) != 1 {
			return cli.Usagef("user:create needs one email address")
		}
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		printLink := fs.Lookup("print-link").Value.String() == "true"
		u, invite, err := CreateUser(ctx, cfg, deps, args[0], fs.Lookup("name").Value.String(), printLink)
		if err != nil {
			return err
		}
		if !printLink {
			_, err = fmt.Fprintf(fs.Output(), "created %s and queued an invite\n", u.ID)
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "created %s\ninvite token, valid for %s (accept it with POST %s/auth/invites/accept):\n%s\n",
			u.ID, cfg.Tokens.TTLFor(tokens.Invite), BasePath, invite)
		return err
	}
}

// CreateUser creates a user and issues an invite. The invite goes to the notifier in the same
// transaction, or with printLink is returned for the operator's terminal instead. The user signs in
// once they hold a role in the realm (user:grant).
func CreateUser(ctx context.Context, cfg Config, deps Deps, email, name string, printLink bool) (users.User, string, error) {
	w, err := newWiring(cfg, deps)
	if err != nil {
		return users.User{}, "", err
	}
	if !printLink && w.notifier == nil {
		return users.User{}, "", fmt.Errorf("%w; pass --print-link to print the invite instead", errNoNotifier)
	}
	var u users.User
	var raw string
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		if u, err = w.users().Create(ctx, tx, users.NewUser{Email: email, Name: name}); err != nil {
			return err
		}
		if raw, err = tokens.Issue(ctx, tx, u.ID, tokens.Invite, cfg.Tokens.TTLFor(tokens.Invite)); err != nil || printLink {
			return err
		}
		return w.notifier.SendInvite(ctx, tx, u, raw)
	})
	if !printLink {
		raw = ""
	}
	return u, raw, err
}

// userRevokeSessions revokes every session of a user, audited as the system.
func userRevokeSessions(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		if len(args) != 1 {
			return cli.Usagef("user:revoke-sessions needs one email address")
		}
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		if err := RevokeSessions(ctx, cfg, deps.DB, args[0]); err != nil {
			return err
		}
		_, err = fmt.Fprintln(fs.Output(), "revoked every session")
		return err
	}
}

// RevokeSessions signs the user with email out of every realm.
func RevokeSessions(ctx context.Context, cfg Config, d *db.DB, email string) error {
	w, err := newWiring(cfg, Deps{DB: d})
	if err != nil {
		return err
	}
	return db.InAppTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.ByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		return w.sessions.RevokeUser(ctx, tx, u.ID)
	})
}

func openForCommand(ctx context.Context, environ []string) (Config, Deps, error) {
	cfg, err := LoadConfig(environ)
	if err != nil {
		return Config{}, Deps{}, errors.New("invalid configuration:\n" + err.Error())
	}
	deps, err := OpenDatabase(ctx, cfg)
	return cfg, deps, err
}
