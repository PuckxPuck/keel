package rbac

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

var roleCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Access is the only writer of roles and grants. Every change takes the realm's access lock, reads
// the facts the rules need inside the transaction, checks the acting principal, and audits.
type Access struct {
	audit      *audit.Recorder
	manage     Code
	catalogues map[string]*Catalogue
	hooks      []Hook
}

// Hook hears about a change to a user's grants inside the change's transaction, so sessions can
// revoke what the change takes away. Every change also moves the access version of each user it
// touches (users.BumpAccess), which is how sessions see it.
type Hook interface {
	UserAccessChanged(ctx context.Context, tx db.Transaction, realm string, user users.ID) error
}

type AccessOption func(*Access)

func WithHook(h Hook) AccessOption { return func(a *Access) { a.hooks = append(a.hooks, h) } }

// NewAccess panics on a missing recorder, policy or catalogue: it runs once at startup.
func NewAccess(rec *audit.Recorder, policy Policy, catalogues map[string]*Catalogue, opts ...AccessOption) *Access {
	if rec == nil || policy.AccessManage == "" || len(catalogues) == 0 {
		panic("rbac: NewAccess needs a recorder, a policy and the realms' catalogues")
	}
	for realm, cat := range catalogues {
		if cat == nil {
			panic("rbac: realm " + realm + " has no catalogue")
		}
	}
	a := &Access{audit: rec, manage: policy.AccessManage, catalogues: maps.Clone(catalogues)}
	for _, o := range opts {
		o(a)
	}
	return a
}

func (a *Access) userChanged(ctx context.Context, tx db.Transaction, realm string, user users.ID) error {
	if err := users.BumpAccess(ctx, tx, user); err != nil {
		return err
	}
	for _, h := range a.hooks {
		if err := h.UserAccessChanged(ctx, tx, realm, user); err != nil {
			return err
		}
	}
	return nil
}

var _ users.Guard = (*Access)(nil)

const lockPrefix = "rbac:access:"

func (a *Access) begin(ctx context.Context, tx db.Transaction, realm string) (*Catalogue, error) {
	cat, ok := a.catalogues[realm]
	if !ok {
		return nil, fmt.Errorf("rbac: unknown realm %q", realm)
	}
	return cat, db.LockIn(ctx, tx, lockPrefix+realm)
}

// Setup creates the built-in roles of realm that do not exist yet; Sync keeps existing ones in step.
func (a *Access) Setup(ctx context.Context, tx db.Transaction, realm string, builtins []Builtin) ([]Role, error) {
	cat, err := a.begin(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	for _, b := range builtins {
		if !roleCodePattern.MatchString(b.Code) {
			return nil, fmt.Errorf("rbac: built-in role code %q must be lower case letters, digits, - and _", b.Code)
		}
		if unknown := cat.Unknown(b.Permissions...); len(unknown) > 0 {
			return nil, fmt.Errorf("rbac: built-in role %s uses permissions missing from the %s catalogue: %v", b.Code, realm, unknown)
		}
	}
	var created []Role
	for _, b := range builtins {
		_, err := RoleByCode(ctx, tx, realm, b.Code)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrRoleNotFound) {
			return nil, err
		}
		at := now(ctx)
		r := Role{
			ID: ids.NewOf[roleTag](), Realm: realm, Code: b.Code, Name: b.Name, Builtin: true, Version: 1,
			Permissions: sortedCodes(b.Permissions), CreatedAt: at, UpdatedAt: at,
		}
		if err := insertRole(ctx, tx, r); err != nil {
			return nil, err
		}
		if err := a.audit.Record(ctx, tx, audit.Event{Action: "role.created", Entity: "role", EntityID: r.ID.String(), After: r}); err != nil {
			return nil, err
		}
		created = append(created, r)
	}
	return created, nil
}

// Sync makes each existing built-in role of realm carry exactly the permissions its definition lists, so
// a database set up before a definition changed catches up (app setup). It records
// role.permissions_synced for each role it changes and moves its holders' access versions. Built-in roles
// cannot be edited through the access API, so nothing an administrator chose is overwritten.
func (a *Access) Sync(ctx context.Context, tx db.Transaction, realm string, builtins []Builtin) ([]Role, error) {
	cat, err := a.begin(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	var changed []Role
	for _, b := range builtins {
		if unknown := cat.Unknown(b.Permissions...); len(unknown) > 0 {
			return nil, fmt.Errorf("rbac: built-in role %s uses permissions missing from the %s catalogue: %v", b.Code, realm, unknown)
		}
		before, err := RoleByCode(ctx, tx, realm, b.Code)
		if errors.Is(err, ErrRoleNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		want := sortedCodes(b.Permissions)
		if !before.Builtin || slices.Equal(sortedCodes(before.Permissions), want) {
			continue
		}
		after := before
		after.Permissions = want
		after.Version, after.UpdatedAt = before.Version+1, now(ctx)
		q := db.Rebind(tx.Dialect(), "UPDATE roles SET version = ?, updated_at = ? WHERE id = ?")
		if _, err := tx.Q().ExecContext(ctx, q, after.Version, after.UpdatedAt, before.ID); err != nil {
			return nil, fmt.Errorf("update role: %w", err)
		}
		if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM role_permissions WHERE role_id = ?"), before.ID); err != nil {
			return nil, fmt.Errorf("update role permissions: %w", err)
		}
		if err := insertPermissions(ctx, tx, before.ID, want); err != nil {
			return nil, err
		}
		event := audit.Event{Action: "role.permissions_synced", Entity: "role", EntityID: before.ID.String(), Before: before, After: after}
		if err := a.audit.Record(ctx, tx, event); err != nil {
			return nil, err
		}
		if err := bumpHolders(ctx, tx, before.ID); err != nil {
			return nil, err
		}
		changed = append(changed, after)
	}
	return changed, nil
}

type grantImage struct {
	RoleID RoleID `json:"roleId"`
	Scope  *Scope `json:"scope,omitempty"`
}

// Grant gives a role of the actor's realm to a user. The actor needs the access-management permission
// where the grant applies and every permission the role carries; nobody grants to themselves.
func (a *Access) Grant(ctx context.Context, tx db.Transaction, actor Principal, g UserRole) error {
	cat, err := a.begin(ctx, tx, actor.Realm)
	if err != nil {
		return err
	}
	role, err := a.roleOf(ctx, tx, actor, g.RoleID)
	if err != nil {
		return err
	}
	if !mayManage(actor, a.manage, g.Scope) {
		return ErrForbidden
	}
	var v []Violation
	if !actor.system {
		if actor.UserID == g.UserID {
			v = append(v, Violation{Rule: RuleOwnRoles})
		}
		if l := lacking(actor, cat, role.Permissions, g.Scope); len(l) > 0 {
			v = append(v, Violation{Rule: RuleExceedsActor, Permissions: l})
		}
	}
	if err := Refuse(v); err != nil {
		return err
	}
	var by *users.ID
	if id, ok := actor.ActingUser(); ok {
		by = &id
	}
	if err := insertGrant(ctx, tx, g, by, now(ctx)); err != nil {
		return err
	}
	if err := a.audit.Record(ctx, tx, audit.Event{
		Action: "user_role.granted", Entity: "user", EntityID: g.UserID.String(),
		After: grantImage{RoleID: g.RoleID, Scope: g.Scope},
	}); err != nil {
		return err
	}
	return a.userChanged(ctx, tx, actor.Realm, g.UserID)
}

// Revoke takes a role grant away. It refuses to leave the realm without an access manager.
func (a *Access) Revoke(ctx context.Context, tx db.Transaction, actor Principal, g UserRole) error {
	if _, err := a.begin(ctx, tx, actor.Realm); err != nil {
		return err
	}
	if _, err := a.roleOf(ctx, tx, actor, g.RoleID); err != nil {
		return err
	}
	grantID, err := grantForUpdate(ctx, tx, g)
	if err != nil {
		return err
	}
	if !mayManage(actor, a.manage, g.Scope) {
		return ErrForbidden
	}
	var v []Violation
	if !actor.system && actor.UserID == g.UserID {
		v = append(v, Violation{Rule: RuleOwnRoles})
	}
	last, err := a.lastAccess(ctx, tx, actor.Realm, func(h holderGrant) bool { return h.id == grantID }, nil)
	if err != nil {
		return err
	}
	if err := Refuse(append(v, last...)); err != nil {
		return err
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM user_roles WHERE id = ?"), grantID); err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}
	if err := a.audit.Record(ctx, tx, audit.Event{
		Action: "user_role.revoked", Entity: "user", EntityID: g.UserID.String(),
		Before: grantImage{RoleID: g.RoleID, Scope: g.Scope},
	}); err != nil {
		return err
	}
	return a.userChanged(ctx, tx, actor.Realm, g.UserID)
}

// SetRolePermissions replaces the permissions of a custom role of the actor's realm, at the version the
// caller read. Adding a permission needs the actor to hold it everywhere; a built-in role is ErrBuiltinRole.
func (a *Access) SetRolePermissions(ctx context.Context, tx db.Transaction, actor Principal, id RoleID, version int, perms []Code) (Role, error) {
	cat, err := a.begin(ctx, tx, actor.Realm)
	if err != nil {
		return Role{}, err
	}
	before, err := a.roleOf(ctx, tx, actor, id)
	if err != nil {
		return Role{}, err
	}
	if !mayManage(actor, a.manage, nil) {
		return Role{}, ErrForbidden
	}
	if before.Builtin {
		return Role{}, ErrBuiltinRole
	}
	if before.Version != version {
		return Role{}, &occ.StaleError{Current: occ.Current{Version: before.Version, ChangedAt: before.UpdatedAt}}
	}
	after := before
	after.Permissions = sortedCodes(perms)
	var v []Violation
	if unknown := cat.Unknown(after.Permissions...); len(unknown) > 0 {
		v = append(v, Violation{Rule: RuleUnknownPermission, Permissions: unknown})
	}
	var added []Code
	for _, p := range after.Permissions {
		if !slices.Contains(before.Permissions, p) {
			added = append(added, p)
		}
	}
	if l := lacking(actor, cat, added, nil); !actor.system && len(l) > 0 {
		v = append(v, Violation{Rule: RuleExceedsActor, Permissions: l})
	}
	if slices.Contains(before.Permissions, a.manage) && !slices.Contains(after.Permissions, a.manage) {
		last, err := a.lastAccess(ctx, tx, actor.Realm, func(h holderGrant) bool { return h.roleID == id }, &id)
		if err != nil {
			return Role{}, err
		}
		v = append(v, last...)
	}
	if err := Refuse(v); err != nil {
		return Role{}, err
	}
	after.Version, after.UpdatedAt = before.Version+1, now(ctx)
	q := db.Rebind(tx.Dialect(), "UPDATE roles SET version = ?, updated_at = ? WHERE id = ?")
	if _, err := tx.Q().ExecContext(ctx, q, after.Version, after.UpdatedAt, id); err != nil {
		return Role{}, fmt.Errorf("update role: %w", err)
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM role_permissions WHERE role_id = ?"), id); err != nil {
		return Role{}, fmt.Errorf("update role permissions: %w", err)
	}
	if err := insertPermissions(ctx, tx, id, after.Permissions); err != nil {
		return Role{}, err
	}
	if err := a.audit.Record(ctx, tx, audit.Event{Action: "role.permissions_changed", Entity: "role", EntityID: id.String(), Before: before, After: after}); err != nil {
		return Role{}, err
	}
	return after, bumpHolders(ctx, tx, id)
}

// DeleteRole deletes a custom role of the actor's realm and every grant of it, at the version the caller
// read; a built-in role is ErrBuiltinRole.
func (a *Access) DeleteRole(ctx context.Context, tx db.Transaction, actor Principal, id RoleID, version int) error {
	if _, err := a.begin(ctx, tx, actor.Realm); err != nil {
		return err
	}
	before, err := a.roleOf(ctx, tx, actor, id)
	if err != nil {
		return err
	}
	if !mayManage(actor, a.manage, nil) {
		return ErrForbidden
	}
	if before.Builtin {
		return ErrBuiltinRole
	}
	if before.Version != version {
		return &occ.StaleError{Current: occ.Current{Version: before.Version, ChangedAt: before.UpdatedAt}}
	}
	if slices.Contains(before.Permissions, a.manage) {
		last, err := a.lastAccess(ctx, tx, actor.Realm, func(h holderGrant) bool { return h.roleID == id }, &id)
		if err != nil {
			return err
		}
		if err := Refuse(last); err != nil {
			return err
		}
	}
	holders, err := holdersOf(ctx, tx, id)
	if err != nil {
		return err
	}
	// Children first: under tenancy a role without a tenant has no foreign key to cascade from.
	for _, q := range []string{"DELETE FROM user_roles WHERE role_id = ?", "DELETE FROM role_permissions WHERE role_id = ?", "DELETE FROM roles WHERE id = ?"} {
		if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), id); err != nil {
			return fmt.Errorf("delete role: %w", err)
		}
	}
	if err := a.audit.Record(ctx, tx, audit.Event{Action: "role.deleted", Entity: "role", EntityID: id.String(), Before: before}); err != nil {
		return err
	}
	for _, u := range holders {
		if err := a.userChanged(ctx, tx, actor.Realm, u); err != nil {
			return err
		}
	}
	return nil
}

// NewRole is a custom role: empty, or with the permissions of CopyFrom plus Permissions.
type NewRole struct {
	Code        string
	Name        string
	CopyFrom    *RoleID
	Permissions []Code
}

const maxRoleName = 200

// CreateRole adds a role to the actor's realm. The actor needs the access-management permission
// everywhere and every permission the new role carries.
func (a *Access) CreateRole(ctx context.Context, tx db.Transaction, actor Principal, in NewRole) (Role, error) {
	cat, err := a.begin(ctx, tx, actor.Realm)
	if err != nil {
		return Role{}, err
	}
	perms := slices.Clone(in.Permissions)
	if in.CopyFrom != nil {
		from, err := a.roleOf(ctx, tx, actor, *in.CopyFrom)
		if err != nil {
			return Role{}, err
		}
		perms = append(perms, from.Permissions...)
	}
	if !mayManage(actor, a.manage, nil) {
		return Role{}, ErrForbidden
	}
	name := strings.TrimSpace(in.Name)
	var v []Violation
	if !roleCodePattern.MatchString(in.Code) {
		v = append(v, Violation{Rule: RuleInvalidRoleCode})
	}
	if name == "" || len([]rune(name)) > maxRoleName {
		v = append(v, Violation{Rule: RuleInvalidRoleName})
	}
	perms = sortedCodes(perms)
	if unknown := cat.Unknown(perms...); len(unknown) > 0 {
		v = append(v, Violation{Rule: RuleUnknownPermission, Permissions: unknown})
	}
	if l := lacking(actor, cat, perms, nil); !actor.system && len(l) > 0 {
		v = append(v, Violation{Rule: RuleExceedsActor, Permissions: l})
	}
	if err := Refuse(v); err != nil {
		return Role{}, err
	}
	if _, err := RoleByCode(ctx, tx, actor.Realm, in.Code); err == nil {
		return Role{}, ErrRoleExists
	} else if !errors.Is(err, ErrRoleNotFound) {
		return Role{}, err
	}
	at := now(ctx)
	r := Role{
		ID: ids.NewOf[roleTag](), Realm: actor.Realm, Code: in.Code, Name: name, Version: 1,
		Permissions: perms, CreatedAt: at, UpdatedAt: at,
	}
	if err := insertRole(ctx, tx, r); err != nil {
		if db.IsUniqueViolation(err) {
			return Role{}, ErrRoleExists
		}
		return Role{}, err
	}
	return r, a.audit.Record(ctx, tx, audit.Event{Action: "role.created", Entity: "role", EntityID: r.ID.String(), After: r})
}

// CheckStatus refuses disabling the last active access manager of any realm. users.Service calls it
// before reading or writing the user, so realm locks come before row locks as in every other change.
func (a *Access) CheckStatus(ctx context.Context, tx db.Transaction, _ users.Actor, target users.ID, to users.Status) error {
	if to != users.Disabled {
		return nil
	}
	realms, err := realmsManagedBy(ctx, tx, target, a.manage)
	if err != nil {
		return err
	}
	for _, realm := range realms {
		if _, ok := a.catalogues[realm]; !ok {
			continue
		}
		if err := db.LockIn(ctx, tx, lockPrefix+realm); err != nil {
			return err
		}
		last, err := a.lastAccess(ctx, tx, realm, func(h holderGrant) bool { return h.userID == target }, nil)
		if err != nil {
			return err
		}
		if err := Refuse(last); err != nil {
			return err
		}
	}
	return nil
}

// roleOf locks the role and treats a role of another realm as missing.
func (a *Access) roleOf(ctx context.Context, tx db.Transaction, actor Principal, id RoleID) (Role, error) {
	role, err := roleForUpdate(ctx, tx, id)
	if err != nil {
		return Role{}, err
	}
	if role.Realm != actor.Realm {
		return Role{}, ErrRoleNotFound
	}
	return role, nil
}

// lastAccess reports the change that removes the grants removed reports (and, when role is set, that
// role's access management) if it leaves the realm with no active holder or no role carrying it.
func (a *Access) lastAccess(ctx context.Context, tx db.Transaction, realm string, removed func(holderGrant) bool, role *RoleID) ([]Violation, error) {
	holders, err := holderGrants(ctx, tx, realm, a.manage)
	if err != nil {
		return nil, err
	}
	var out []Violation
	if slices.ContainsFunc(holders, removed) && !slices.ContainsFunc(holders, func(h holderGrant) bool { return !removed(h) }) {
		out = append(out, Violation{Rule: RuleLastAccessUser, Permissions: []Code{a.manage}})
	}
	if role == nil {
		return out, nil
	}
	roles, err := rolesWithAccess(ctx, tx, realm, a.manage)
	if err != nil {
		return nil, err
	}
	if slices.Contains(roles, *role) && len(roles) == 1 {
		out = append(out, Violation{Rule: RuleLastAccessRole, Permissions: []Code{a.manage}})
	}
	return out, nil
}

func now(ctx context.Context) time.Time {
	return clock.Business(ctx).Now().UTC().Truncate(time.Microsecond)
}

func sortedCodes(codes []Code) []Code {
	out := slices.Clone(codes)
	slices.SortFunc(out, func(a, b Code) int { return strings.Compare(string(a), string(b)) })
	return slices.Compact(out)
}
