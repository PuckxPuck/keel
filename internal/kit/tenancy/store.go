package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// tenants, tenant_domains and memberships are global tables (no row-level security): they are read
// before any tenant is chosen, and only the operator pool writes them. The tenant tables written here
// from an operator transaction name the tenant, since no setting fills the column default there.

const tenantColumns = "id, slug, name, status, status_reason, version, created_at, updated_at"

func scanTenant(rows *sql.Rows) (Tenant, error) {
	var t Tenant
	var reason sql.NullString
	if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &reason, &t.Version, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	t.StatusReason = reason.String
	return t, nil
}

func oneTenant(ctx context.Context, tx db.Transaction, query string, args ...any) (Tenant, error) {
	rows, err := tx.Q().QueryContext(ctx, "SELECT "+tenantColumns+" FROM tenants "+query, args...)
	if err != nil {
		return Tenant{}, fmt.Errorf("load tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return Tenant{}, errors.Join(rows.Err(), ErrNotFound)
	}
	t, err := scanTenant(rows)
	if err != nil {
		return Tenant{}, err
	}
	return t, rows.Err()
}

// Get reads a tenant.
func Get(ctx context.Context, tx db.Transaction, id ID) (Tenant, error) {
	return oneTenant(ctx, tx, "WHERE id = $1", id)
}

// BySlug reads the tenant with slug.
func BySlug(ctx context.Context, tx db.Transaction, slug string) (Tenant, error) {
	return oneTenant(ctx, tx, "WHERE slug = $1", normaliseSlug(slug))
}

// ByDomain reads the tenant a custom domain belongs to.
func ByDomain(ctx context.Context, tx db.Transaction, host string) (Tenant, error) {
	return oneTenant(ctx, tx, "WHERE id = (SELECT tenant_id FROM tenant_domains WHERE host = $1)", host)
}

// List reads tenants ordered by slug, those after the given slug when after is set; operators only.
func List(ctx context.Context, tx db.Tx[db.Operator], after string, limit int) ([]Tenant, error) {
	rows, err := tx.Q().QueryContext(ctx, "SELECT "+tenantColumns+" FROM tenants WHERE slug > $1 ORDER BY slug LIMIT $2", after, limit)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Membership is a user's entry to a tenant.
type Membership struct {
	Tenant  Tenant `json:"tenant"`
	Default bool   `json:"default"`
}

// Memberships lists the tenants user may work in (active memberships), the default first.
func Memberships(ctx context.Context, tx db.Transaction, user users.ID) ([]Membership, error) {
	rows, err := tx.Q().QueryContext(ctx, `SELECT t.id, t.slug, t.name, t.status, t.status_reason, t.version, t.created_at, t.updated_at, m.is_default
		FROM memberships m JOIN tenants t ON t.id = m.tenant_id
		WHERE m.user_id = $1 AND m.status = 'active' ORDER BY m.is_default DESC, t.slug`, user)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Membership
	for rows.Next() {
		var m Membership
		var reason sql.NullString
		t := &m.Tenant
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &reason, &t.Version, &t.CreatedAt, &t.UpdatedAt, &m.Default); err != nil {
			return nil, err
		}
		t.StatusReason = reason.String
		out = append(out, m)
	}
	return out, rows.Err()
}

// IsMember is true when user holds an active membership in tenant.
func IsMember(ctx context.Context, tx db.Transaction, tenant ID, user users.ID) (bool, error) {
	rows, err := tx.Q().QueryContext(ctx, "SELECT 1 FROM memberships WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'", tenant, user)
	if err != nil {
		return false, fmt.Errorf("load membership: %w", err)
	}
	defer func() { _ = rows.Close() }()
	found := rows.Next()
	return found, rows.Err()
}

// entry reads the tenant and whether user (when set) is an active member, in one statement per request.
func entry(ctx context.Context, tx db.Transaction, id uuid.UUID, user *users.ID) (Tenant, bool, error) {
	rows, err := tx.Q().QueryContext(ctx, `SELECT `+tenantColumns+`,
		EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = tenants.id AND m.user_id = $2 AND m.status = 'active')
		FROM tenants WHERE id = $1`, id, user)
	if err != nil {
		return Tenant{}, false, fmt.Errorf("load tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return Tenant{}, false, errors.Join(rows.Err(), ErrNotFound)
	}
	var t Tenant
	var reason sql.NullString
	var member bool
	if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &reason, &t.Version, &t.CreatedAt, &t.UpdatedAt, &member); err != nil {
		return Tenant{}, false, err
	}
	t.StatusReason = reason.String
	return t, member, rows.Err()
}

// landing is where a sign-in without a tenant host goes: the default membership, else the oldest,
// skipping suspended tenants.
func landing(ctx context.Context, tx db.Transaction, user users.ID) (uuid.UUID, bool, error) {
	rows, err := tx.Q().QueryContext(ctx, `SELECT m.tenant_id FROM memberships m JOIN tenants t ON t.id = m.tenant_id
		WHERE m.user_id = $1 AND m.status = 'active' AND t.status <> 'suspended'
		ORDER BY m.is_default DESC, m.created_at, m.tenant_id LIMIT 1`, user)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("load memberships: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return uuid.Nil, false, rows.Err()
	}
	var id uuid.UUID
	if err := rows.Scan(&id); err != nil {
		return uuid.Nil, false, err
	}
	return id, true, rows.Err()
}

// AddMember gives user entry to tenant; the membership becomes their default when they have none.
func AddMember(ctx context.Context, tx db.Tx[db.Operator], tenant ID, user users.ID) error {
	_, err := tx.Q().ExecContext(ctx, `INSERT INTO memberships (tenant_id, user_id, status, is_default, created_at)
		VALUES ($1, $2, 'active', NOT EXISTS (SELECT 1 FROM memberships WHERE user_id = $2 AND is_default), $3)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET status = 'active'`, tenant, user, now(ctx))
	switch {
	case db.IsForeignKeyViolation(err):
		return users.ErrNotFound
	case err != nil:
		return fmt.Errorf("add member: %w", err)
	}
	return users.BumpAccess(ctx, tx, user)
}

// RemoveMember ends user's entry to tenant at once (the guard reads memberships on every request). Their
// sessions working there leave it, so they can switch to another tenant or sign out. API keys and
// devices are the tenant's, not the member's, and keep working.
func RemoveMember(ctx context.Context, tx db.Tx[db.Operator], tenant ID, user users.ID) error {
	if _, err := tx.Q().ExecContext(ctx, "DELETE FROM memberships WHERE tenant_id = $1 AND user_id = $2", tenant, user); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	if _, err := tx.Q().ExecContext(ctx, "UPDATE sessions SET current_tenant_id = NULL WHERE user_id = $1 AND current_tenant_id = $2", user, tenant); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return users.BumpAccess(ctx, tx, user)
}

// leaveTenant takes the request's session out of a tenant its user is no longer a member of.
func leaveTenant(ctx context.Context, tx db.Transaction, session, tenant uuid.UUID) error {
	if _, err := tx.Q().ExecContext(ctx, "UPDATE sessions SET current_tenant_id = NULL WHERE id = $1 AND current_tenant_id = $2", session, tenant); err != nil {
		return fmt.Errorf("leave tenant: %w", err)
	}
	return nil
}

func insertTenant(ctx context.Context, tx db.Transaction, t Tenant) error {
	_, err := tx.Q().ExecContext(ctx, "INSERT INTO tenants ("+tenantColumns+") VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)",
		t.ID, t.Slug, t.Name, string(t.Status), t.Version, t.CreatedAt, t.UpdatedAt)
	if db.IsUniqueViolation(err) {
		return ErrSlugTaken
	}
	if err != nil {
		return fmt.Errorf("insert tenant: %w", err)
	}
	return nil
}

func insertDomain(ctx context.Context, tx db.Transaction, tenant ID, host string, at time.Time) error {
	_, err := tx.Q().ExecContext(ctx, "INSERT INTO tenant_domains (host, tenant_id, created_at) VALUES ($1, $2, $3)", host, tenant, at)
	if db.IsUniqueViolation(err) {
		return fmt.Errorf("%w: domain %s is taken", ErrInvalid, host)
	}
	return err
}

// insertTemplateRoles copies the templates into tenant and returns the id of each by code.
func insertTemplateRoles(ctx context.Context, tx db.Transaction, tenant ID, realm string, templates []rbac.Builtin, at time.Time) (map[string]uuid.UUID, error) {
	out := map[string]uuid.UUID{}
	for _, b := range templates {
		id := ids.New()
		if _, err := tx.Q().ExecContext(ctx, `INSERT INTO roles (id, tenant_id, realm, code, name, builtin, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, true, 1, $6, $6)`, id, tenant, realm, b.Code, b.Name, at); err != nil {
			return nil, fmt.Errorf("insert role %s: %w", b.Code, err)
		}
		for _, p := range b.Permissions {
			if _, err := tx.Q().ExecContext(ctx, "INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, $3)",
				tenant, id, string(p)); err != nil {
				return nil, fmt.Errorf("insert role permission: %w", err)
			}
		}
		out[b.Code] = id
	}
	return out, nil
}

func grantInTenant(ctx context.Context, tx db.Transaction, tenant ID, user users.ID, role uuid.UUID, at time.Time) error {
	_, err := tx.Q().ExecContext(ctx, "INSERT INTO user_roles (id, tenant_id, user_id, role_id, created_at) VALUES ($1, $2, $3, $4, $5)",
		ids.New(), tenant, user, role, at)
	if err != nil {
		return fmt.Errorf("grant owner role: %w", err)
	}
	return nil
}

func setStatus(ctx context.Context, tx db.Transaction, id ID, status Status, reason *string, at time.Time) error {
	res, err := tx.Q().ExecContext(ctx, "UPDATE tenants SET status = $2, status_reason = $3, version = version + 1, updated_at = $4 WHERE id = $1",
		id, string(status), reason, at)
	if err != nil {
		return fmt.Errorf("set tenant state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, ErrNotFound)
	}
	return nil
}

// endSessions deletes every session working in tenant (suspension).
func endSessions(ctx context.Context, tx db.Transaction, id ID) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, "DELETE FROM sessions WHERE current_tenant_id = $1", id)
	if err != nil {
		return 0, fmt.Errorf("end tenant sessions: %w", err)
	}
	return res.RowsAffected()
}

func now(ctx context.Context) time.Time {
	return wallNow(ctx)
}
