package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type roleTag struct{}

type RoleID = ids.ID[roleTag]

type Role struct {
	ID          RoleID    `json:"id"`
	Realm       string    `json:"realm"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Builtin     bool      `json:"builtin"`
	Version     int       `json:"version"`
	Permissions []Code    `json:"permissions"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Builtin is a role the app defines in code; setup creates it once and never overwrites it.
type Builtin struct {
	Code        string
	Name        string
	Permissions []Code
}

// UserRole is one grant of a role to a user, everywhere (nil Scope) or within a scope.
type UserRole struct {
	UserID users.ID
	RoleID RoleID
	Scope  *Scope
}

const selectRole = "SELECT id, realm, code, name, builtin, version, created_at, updated_at FROM roles "

func insertRole(ctx context.Context, tx db.Transaction, r Role) error {
	q := db.Rebind(tx.Dialect(), "INSERT INTO roles (id, realm, code, name, builtin, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.Q().ExecContext(ctx, q, r.ID, r.Realm, r.Code, r.Name, r.Builtin, r.Version, r.CreatedAt, r.UpdatedAt); err != nil {
		return fmt.Errorf("insert role %s: %w", r.Code, err)
	}
	return insertPermissions(ctx, tx, r.ID, r.Permissions)
}

func insertPermissions(ctx context.Context, tx db.Transaction, id RoleID, perms []Code) error {
	q := db.Rebind(tx.Dialect(), "INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
	for _, p := range perms {
		if _, err := tx.Q().ExecContext(ctx, q, id, string(p)); err != nil {
			return fmt.Errorf("insert role permission: %w", err)
		}
	}
	return nil
}

func RoleByCode(ctx context.Context, tx db.Transaction, realm, code string) (Role, error) {
	return oneRole(ctx, tx, selectRole+"WHERE realm = ? AND code = ?", realm, code)
}

// roleForUpdate reads the role as it is now and locks it until tx ends.
func roleForUpdate(ctx context.Context, tx db.Transaction, id RoleID) (Role, error) {
	return oneRole(ctx, tx, selectRole+"WHERE id = ? FOR UPDATE", id)
}

func oneRole(ctx context.Context, tx db.Transaction, query string, args ...any) (Role, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), query), args...)
	if err != nil {
		return Role{}, fmt.Errorf("load role: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Role{}, err
		}
		return Role{}, ErrRoleNotFound
	}
	var r Role
	if err := rows.Scan(&r.ID, &r.Realm, &r.Code, &r.Name, &r.Builtin, &r.Version, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return Role{}, err
	}
	if err := rows.Close(); err != nil {
		return Role{}, err
	}
	perms, err := rolePermissions(ctx, tx, r.ID)
	r.Permissions = perms
	return r, err
}

func rolePermissions(ctx context.Context, tx db.Transaction, id RoleID) ([]Code, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission"), id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Code
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, Code(c))
	}
	return out, rows.Err()
}

func insertGrant(ctx context.Context, tx db.Transaction, g UserRole, by *users.ID, now time.Time) error {
	var scopeType *string
	var scopeID *uuid.UUID
	if g.Scope != nil {
		scopeType, scopeID = &g.Scope.Type, &g.Scope.ID
	}
	q := db.Rebind(tx.Dialect(), "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
	_, err := tx.Q().ExecContext(ctx, q, ids.New(), g.UserID, g.RoleID, scopeType, scopeID, by, now)
	switch {
	case db.IsUniqueViolation(err):
		return ErrAlreadyGranted
	case db.IsForeignKeyViolation(err):
		return users.ErrNotFound
	case err != nil:
		return fmt.Errorf("grant role: %w", err)
	}
	return nil
}

// grantForUpdate finds and locks one grant.
func grantForUpdate(ctx context.Context, tx db.Transaction, g UserRole) (uuid.UUID, error) {
	q := "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type IS NULL FOR UPDATE"
	args := []any{g.UserID, g.RoleID}
	if g.Scope != nil {
		q = "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ? FOR UPDATE"
		args = append(args, g.Scope.Type, g.Scope.ID)
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), args...)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("load grant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return uuid.UUID{}, err
		}
		return uuid.UUID{}, ErrGrantNotFound
	}
	var id uuid.UUID
	if err := rows.Scan(&id); err != nil {
		return uuid.UUID{}, err
	}
	return id, rows.Err()
}

type holderGrant struct {
	id     uuid.UUID
	userID users.ID
	roleID RoleID
}

// holderGrants lists the unscoped grants of manage in realm held by active users. The fact queries are
// locking reads: they see the latest commit even when tx read from an older snapshot first (MySQL's
// repeatable read). Postgres allows no DISTINCT or aggregate with FOR SHARE, so Go dedupes.
func holderGrants(ctx context.Context, tx db.Transaction, realm string, manage Code) ([]holderGrant, error) {
	q := db.Rebind(tx.Dialect(), `SELECT ur.id, ur.user_id, ur.role_id FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN users u ON u.id = ur.user_id
		WHERE r.realm = ? AND rp.permission = ? AND ur.scope_type IS NULL AND u.status = ?
		FOR SHARE`)
	rows, err := tx.Q().QueryContext(ctx, q, realm, string(manage), string(users.Active))
	if err != nil {
		return nil, fmt.Errorf("load access holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []holderGrant
	for rows.Next() {
		var g holderGrant
		if err := rows.Scan(&g.id, &g.userID, &g.roleID); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// rolesWithAccess lists the roles of realm carrying manage.
func rolesWithAccess(ctx context.Context, tx db.Transaction, realm string, manage Code) ([]RoleID, error) {
	q := db.Rebind(tx.Dialect(), `SELECT r.id FROM roles r JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.realm = ? AND rp.permission = ? FOR SHARE`)
	return scanIDs[roleTag](ctx, tx, q, realm, string(manage))
}

// realmsManagedBy lists the realms where user holds manage everywhere, whatever the user's status.
func realmsManagedBy(ctx context.Context, tx db.Transaction, user users.ID, manage Code) ([]string, error) {
	q := db.Rebind(tx.Dialect(), `SELECT r.realm FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = ? AND rp.permission = ? AND ur.scope_type IS NULL
		FOR SHARE`)
	rows, err := tx.Q().QueryContext(ctx, q, user, string(manage))
	if err != nil {
		return nil, fmt.Errorf("load managed realms: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var realm string
		if err := rows.Scan(&realm); err != nil {
			return nil, err
		}
		if !slices.Contains(out, realm) {
			out = append(out, realm)
		}
	}
	slices.Sort(out)
	return out, rows.Err()
}

func scanIDs[T any](ctx context.Context, tx db.Transaction, q string, args ...any) ([]ids.ID[T], error) {
	rows, err := tx.Q().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ids.ID[T]
	for rows.Next() {
		var id ids.ID[T]
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// holdersOf lists the users holding role, each once.
func holdersOf(ctx context.Context, tx db.Transaction, role RoleID) ([]users.ID, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT user_id FROM user_roles WHERE role_id = ?"), role)
	if err != nil {
		return nil, fmt.Errorf("load role holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []users.ID
	for rows.Next() {
		var id users.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// Holders lists the active users holding perm everywhere in realm, each once: who to tell about a
// change in their area. Under tenancy a tenant transaction sees its own tenant's grants only.
func Holders(ctx context.Context, tx db.Transaction, realm string, perm Code) ([]users.ID, error) {
	q := db.Rebind(tx.Dialect(), `SELECT DISTINCT ur.user_id FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN users u ON u.id = ur.user_id
		WHERE r.realm = ? AND rp.permission = ? AND ur.scope_type IS NULL AND u.status = ?
		ORDER BY ur.user_id`)
	rows, err := tx.Q().QueryContext(ctx, q, realm, string(perm), string(users.Active))
	if err != nil {
		return nil, fmt.Errorf("load holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []users.ID
	for rows.Next() {
		var id users.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// bumpHolders moves the access version of every user holding role.
func bumpHolders(ctx context.Context, tx db.Transaction, role RoleID) error {
	q := db.Rebind(tx.Dialect(), "UPDATE users SET access_version = access_version + 1 WHERE id IN (SELECT user_id FROM user_roles WHERE role_id = ?)")
	if _, err := tx.Q().ExecContext(ctx, q, role); err != nil {
		return fmt.Errorf("bump access versions: %w", err)
	}
	return nil
}

// Loader builds principals for one realm from the database.
type Loader struct {
	realm string
	cat   *Catalogue
}

func NewLoader(realm string, cat *Catalogue) Loader { return Loader{realm: realm, cat: cat} }

// Load returns the user's permissions in the realm. Codes the catalogue no longer holds are ignored
// with a warning, so removing a permission from code never needs a data migration first.
func (l Loader) Load(ctx context.Context, tx db.Transaction, userID users.ID) (Principal, error) {
	u, err := users.Get(ctx, tx, userID)
	if err != nil {
		return Principal{}, err
	}
	if u.Status != users.Active {
		return Principal{}, ErrUserDisabled
	}
	q := db.Rebind(tx.Dialect(), `SELECT rp.permission, ur.scope_type, ur.scope_id FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = ? AND r.realm = ?`)
	rows, err := tx.Q().QueryContext(ctx, q, userID, l.realm)
	if err != nil {
		return Principal{}, fmt.Errorf("load permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var grants []Grant
	for rows.Next() {
		var perm string
		var scopeType, scopeID sql.NullString
		if err := rows.Scan(&perm, &scopeType, &scopeID); err != nil {
			return Principal{}, err
		}
		if !l.cat.Has(Code(perm)) {
			logx.From(ctx).Warn("ignoring a permission missing from the catalogue", "permission", perm, "realm", l.realm)
			continue
		}
		g := Grant{Perm: Code(perm)}
		if scopeType.Valid {
			id, err := uuid.Parse(scopeID.String)
			if err != nil {
				return Principal{}, fmt.Errorf("scope id: %w", err)
			}
			g.Scope = &Scope{Type: scopeType.String, ID: id}
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return Principal{}, err
	}
	return NewPrincipal(userID, l.realm, grants...), nil
}

// HeldRole is a role a user holds, everywhere (nil Scope) or within a scope.
type HeldRole struct {
	RoleID RoleID `json:"roleId"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Scope  *Scope `json:"scope,omitempty"`
}

// RolesOf lists the roles user holds in realm, by code.
func RolesOf(ctx context.Context, tx db.Transaction, realm string, user users.ID) ([]HeldRole, error) {
	q := db.Rebind(tx.Dialect(), `SELECT r.id, r.code, r.name, ur.scope_type, ur.scope_id FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.realm = ? ORDER BY r.code, ur.scope_type, ur.scope_id`)
	rows, err := tx.Q().QueryContext(ctx, q, user, realm)
	if err != nil {
		return nil, fmt.Errorf("load roles of user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HeldRole
	for rows.Next() {
		var h HeldRole
		var scopeType, scopeID sql.NullString
		if err := rows.Scan(&h.RoleID, &h.Code, &h.Name, &scopeType, &scopeID); err != nil {
			return nil, err
		}
		if scopeType.Valid {
			id, err := uuid.Parse(scopeID.String)
			if err != nil {
				return nil, fmt.Errorf("scope id: %w", err)
			}
			h.Scope = &Scope{Type: scopeType.String, ID: id}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HoldsAnyRole is true when user holds at least one role in realm.
func HoldsAnyRole(ctx context.Context, tx db.Transaction, realm string, user users.ID) (bool, error) {
	q := db.Rebind(tx.Dialect(), `SELECT ur.id FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.realm = ? LIMIT 1`)
	held, err := scanIDs[roleTag](ctx, tx, q, user, realm)
	return len(held) > 0, err
}
