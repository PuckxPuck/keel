// Package apikeys issues API keys that act as service principals on the api realm: a secret-scanner
// friendly format with a checksum, the secret stored as SHA-256 and compared in constant time, scopes
// drawn from API-grantable permissions the creator holds, optional expiry and address allowlist, and
// revocation that takes effect on the next request (the key row is read on every request; D34).
package apikeys

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

// Config is APP_APIKEY_*. An empty Prefix means the app's name. LeakSecrets are the Standard Webhooks
// secrets of the secret-scanning partner that reports leaked keys; empty turns the report off.
type Config struct {
	Prefix      string          `env:"PREFIX"`
	LeakSecrets []config.Secret `env:"LEAK_SECRETS"`
}

func (c Config) Validate(prod bool) error {
	var errs []error
	if c.Prefix != "" && !ValidPrefix(c.Prefix) {
		errs = append(errs, fmt.Errorf("API key prefix %q must be 2 to 16 lower case letters and digits, starting with a letter", c.Prefix))
	}
	if len(c.LeakSecrets) > 0 {
		secrets := make([]string, len(c.LeakSecrets))
		for i, s := range c.LeakSecrets {
			secrets[i] = s.Reveal()
		}
		if _, err := webhook.NewVerifier(webhook.Options{Source: "apikey-leaks", Secrets: secrets, Production: prod}); err != nil {
			errs = append(errs, fmt.Errorf("API key leak secrets: %w", err))
		}
	}
	return errors.Join(errs...)
}

type keyTag struct{}

type ID = ids.ID[keyTag]

// ParseID reads a key id from a path parameter.
func ParseID(raw string) (ID, error) { return ids.Parse[keyTag](raw) }

// Key is a key as the app shows it after creation; the secret is never stored.
type Key struct {
	ID           ID          `json:"id"`
	Name         string      `json:"name"`
	Hint         string      `json:"hint" doc:"The key's prefix and last four characters"`
	Scopes       []rbac.Code `json:"scopes"`
	CreatedBy    *users.ID   `json:"createdBy"`
	CreatedAt    time.Time   `json:"createdAt"`
	ExpiresAt    *time.Time  `json:"expiresAt"`
	LastUsedAt   *time.Time  `json:"lastUsedAt"`
	LastUsedIP   *string     `json:"lastUsedIp"`
	AllowedCIDRs []string    `json:"allowedCidrs"`
	RevokedAt    *time.Time  `json:"revokedAt"`
	// RateClass replaces the per-key rate-limit class for this key; set from the shell only.
	RateClass  string `json:"-"`
	remindedAt *time.Time
}

const (
	maxName   = 100
	maxScopes = 100
	maxCIDRs  = 20
	// touchEvery throttles last_used writes.
	touchEvery         = time.Minute
	RuleNotGrantable   = "not_api_grantable"
	CodeInvalidKey     = "invalid_api_key"
	codeInvalidRequest = "validation_failed"
)

var (
	ErrNotFound = errors.New("API key not found")
	// ErrInvalidKey is every refusal of a presented key: malformed, unknown, wrong secret, revoked,
	// expired or from an address outside its allowlist.
	ErrInvalidKey   = errors.New("the API key is invalid")
	ErrInvalidInput = errors.New("name must be 1 to 100 characters, at most 100 scopes and 20 CIDRs, and the expiry in the future")
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, err.Error()), true
	case errors.Is(err, ErrInvalidKey):
		return problem.New(http.StatusUnauthorized, CodeInvalidKey, err.Error()), true
	case errors.Is(err, ErrInvalidInput):
		return problem.New(http.StatusUnprocessableEntity, codeInvalidRequest, err.Error()), true
	}
	return nil, false
}

type Options struct {
	Format Format
	// Realm is the realm keys authenticate on (api); Catalogue is the permission catalogue their scopes
	// come from, and Manage the permission that creates and revokes them.
	Realm     string
	Catalogue *rbac.Catalogue
	Manage    rbac.Code
	Audit     *audit.Recorder
	// OnLeak runs in the transaction that revokes a reported key, to tell the tenant (a mail job).
	OnLeak func(ctx context.Context, tx db.Transaction, k Key, r Leak) error
}

type Service struct {
	format    Format
	realm     string
	catalogue *rbac.Catalogue
	manage    rbac.Code
	audit     *audit.Recorder
	onLeak    func(ctx context.Context, tx db.Transaction, k Key, r Leak) error
}

func New(o Options) (*Service, error) {
	switch {
	case !ValidPrefix(o.Format.Prefix) || (o.Format.Env != EnvLive && o.Format.Env != EnvTest):
		return nil, fmt.Errorf("apikeys: prefix %q or environment %q is invalid", o.Format.Prefix, o.Format.Env)
	case o.Realm == "" || o.Catalogue == nil || o.Manage == "" || o.Audit == nil:
		return nil, errors.New("apikeys: a realm, a catalogue, a manage permission and an audit recorder are required")
	}
	return &Service{format: o.Format, realm: o.Realm, catalogue: o.Catalogue, manage: o.Manage, audit: o.Audit, onLeak: o.OnLeak}, nil
}

// Format is the key shape this service issues and accepts.
func (s *Service) Format() Format { return s.format }

// NewKey is what Create needs. AllowedCIDRs, when set, limit the addresses the key works from.
type NewKey struct {
	Name         string
	Scopes       []rbac.Code
	ExpiresAt    *time.Time
	AllowedCIDRs []string
	RateClass    string
}

// Create issues a key and returns its plaintext, shown once. The actor needs the manage permission and
// every scope, and each scope must be API-grantable; the system actor skips only what it holds.
func (s *Service) Create(ctx context.Context, tx db.Transaction, actor rbac.Principal, in NewKey) (string, Key, error) {
	if !actor.IsSystem() && !actor.Can(s.manage) {
		return "", Key{}, rbac.ErrForbidden
	}
	in.Name = strings.TrimSpace(in.Name)
	cidrs, err := parseCIDRs(in.AllowedCIDRs)
	t := now(ctx)
	if err != nil || in.Name == "" || utf8.RuneCountInString(in.Name) > maxName || len(in.Scopes) > maxScopes ||
		(in.ExpiresAt != nil && !in.ExpiresAt.After(t)) || len(in.RateClass) > 32 {
		return "", Key{}, ErrInvalidInput
	}
	scopes := slices.Clone(in.Scopes)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	if err := rbac.Refuse(s.violations(actor, scopes)); err != nil {
		return "", Key{}, err
	}
	k := Key{ID: ids.NewOf[keyTag](), Name: in.Name, Scopes: scopes, CreatedAt: t, AllowedCIDRs: cidrs, RateClass: in.RateClass}
	if by, ok := actor.ActingUser(); ok {
		k.CreatedBy = &by
	}
	if in.ExpiresAt != nil {
		e := in.ExpiresAt.UTC().Truncate(time.Microsecond)
		k.ExpiresAt = &e
	}
	plain, hash := s.format.newKey(k.ID.UUID())
	k.Hint = s.format.hint(plain)
	q := db.Rebind(tx.Dialect(), `INSERT INTO api_keys (id, name, hint, secret_hash, scopes, created_by, created_at, expires_at, allowed_cidrs, rate_class)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.Q().ExecContext(ctx, q, k.ID, k.Name, k.Hint, hash, joinCodes(scopes), k.CreatedBy, k.CreatedAt, k.ExpiresAt,
		nullable(strings.Join(cidrs, " ")), nullable(k.RateClass)); err != nil {
		return "", Key{}, fmt.Errorf("apikeys: create: %w", err)
	}
	// Under tenancy the key's tenant (the column default) is also kept where a presented key can be
	// located before any tenant transaction exists.
	if tx.Tenancy() {
		if _, err := tx.Q().ExecContext(ctx, "INSERT INTO api_key_tenants (key_id) VALUES ($1)", k.ID); err != nil {
			return "", Key{}, fmt.Errorf("apikeys: create: %w", err)
		}
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "apikey.created", Entity: "api_key", EntityID: k.ID.String(), After: k}); err != nil {
		return "", Key{}, err
	}
	return plain, k, nil
}

func (s *Service) violations(actor rbac.Principal, scopes []rbac.Code) []rbac.Violation {
	var unknown, notGrantable, notHeld []rbac.Code
	for _, code := range scopes {
		p, ok := s.catalogue.Get(code)
		switch {
		case !ok:
			unknown = append(unknown, code)
		case !p.APIGrantable:
			notGrantable = append(notGrantable, code)
		case !actor.IsSystem() && !actor.Can(code):
			notHeld = append(notHeld, code)
		}
	}
	var v []rbac.Violation
	for _, r := range []struct {
		rule  string
		perms []rbac.Code
	}{{rbac.RuleUnknownPermission, unknown}, {RuleNotGrantable, notGrantable}, {rbac.RuleExceedsActor, notHeld}} {
		if len(r.perms) > 0 {
			v = append(v, rbac.Violation{Rule: r.rule, Permissions: r.perms})
		}
	}
	return v
}

// Revoke stops a live key at once: the next request reads the revoked row.
func (s *Service) Revoke(ctx context.Context, tx db.Transaction, actor rbac.Principal, id ID) error {
	if !actor.IsSystem() && !actor.Can(s.manage) {
		return rbac.ErrForbidden
	}
	var by *users.ID
	if u, ok := actor.ActingUser(); ok {
		by = &u
	}
	if err := revoke(ctx, tx, id, by); err != nil {
		return err
	}
	return s.audit.Record(ctx, tx, audit.Event{Action: "apikey.revoked", Entity: "api_key", EntityID: id.String()})
}

func revoke(ctx context.Context, tx db.Transaction, id ID, by *users.ID) error {
	q := db.Rebind(tx.Dialect(), "UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL")
	res, err := tx.Q().ExecContext(ctx, q, now(ctx), by, id)
	if err != nil {
		return fmt.Errorf("apikeys: revoke: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errors.Join(err, ErrNotFound)
	}
	return nil
}

// Resolved is a presented key that checked out: its row and the principal it acts as.
type Resolved struct {
	Key       Key
	Principal rbac.Principal
}

// Resolve checks a presented key against its row (revocation, expiry and the address allowlist apply on
// this request) and records its use at most once a minute, never waiting for it. Every refusal is
// ErrInvalidKey. tx is the one the key's Locator and TxRunner opened.
func (s *Service) Resolve(ctx context.Context, tx db.Transaction, raw string, from netip.Addr) (Resolved, error) {
	id, hash, err := s.format.Parse(raw)
	if err != nil {
		return Resolved{}, ErrInvalidKey
	}
	k, stored, found, err := load(ctx, tx, ids.FromUUID[keyTag](id))
	if err != nil {
		return Resolved{}, err
	}
	t := now(ctx)
	switch {
	case !found || subtle.ConstantTimeCompare(hash, stored) != 1:
		return Resolved{}, ErrInvalidKey
	case k.RevokedAt != nil, k.ExpiresAt != nil && !t.Before(*k.ExpiresAt):
		return Resolved{}, ErrInvalidKey
	case len(k.AllowedCIDRs) > 0 && !allowed(k.AllowedCIDRs, from):
		return Resolved{}, ErrInvalidKey
	}
	if k.LastUsedAt == nil || t.Sub(*k.LastUsedAt) >= touchEvery {
		if err := touch(ctx, tx, k.ID, t, from); err != nil {
			return Resolved{}, err
		}
	}
	grants := make([]rbac.Grant, 0, len(k.Scopes))
	for _, code := range k.Scopes {
		if p, ok := s.catalogue.Get(code); ok && p.APIGrantable {
			grants = append(grants, rbac.Grant{Perm: code})
		}
	}
	p := rbac.NewSubject(rbac.SubjectAPIKey, k.ID.UUID(), s.realm, grants...)
	if tenant, ok := db.TenantOf(ctx); ok {
		p = p.InTenant(tenant)
	}
	return Resolved{Key: k, Principal: p}, nil
}

// touch records the use unless another transaction holds the row (a revoke, a reminder job): the
// request then goes on without waiting, and a later one records it.
func touch(ctx context.Context, tx db.Transaction, id ID, at time.Time, from netip.Addr) error {
	q := db.Rebind(tx.Dialect(), "SELECT id FROM api_keys WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= ?) FOR UPDATE SKIP LOCKED")
	free, err := lockFree(ctx, tx, q, id, at.Add(-touchEvery))
	if err != nil || !free {
		return err
	}
	var ip *string
	if from.IsValid() {
		v := from.String()
		ip = &v
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE api_keys SET last_used_at = ?, last_used_ip = ? WHERE id = ?"), at, ip, id); err != nil {
		return fmt.Errorf("apikeys: record use: %w", err)
	}
	return nil
}

func lockFree(ctx context.Context, tx db.Transaction, q string, args ...any) (bool, error) {
	rows, err := tx.Q().QueryContext(ctx, q, args...)
	if err != nil {
		return false, fmt.Errorf("apikeys: record use: %w", err)
	}
	defer func() { _ = rows.Close() }()
	free := rows.Next()
	return free, errors.Join(rows.Err(), rows.Close())
}

func allowed(cidrs []string, from netip.Addr) bool {
	if !from.IsValid() {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(from.Unmap()) {
			return true
		}
	}
	return false
}

func parseCIDRs(in []string) ([]string, error) {
	if len(in) > maxCIDRs {
		return nil, ErrInvalidInput
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, ErrInvalidInput
		}
		out = append(out, p.Masked().String())
	}
	return out, nil
}

const selectKey = `SELECT id, name, hint, secret_hash, scopes, created_by, created_at, expires_at, last_used_at, last_used_ip,
	allowed_cidrs, revoked_at, rate_class, expiry_reminded_at FROM api_keys `

func scanKey(rows *sql.Rows) (Key, []byte, error) {
	var k Key
	var hash []byte
	var scopes string
	var cidrs, rateClass sql.NullString
	if err := rows.Scan(&k.ID, &k.Name, &k.Hint, &hash, &scopes, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt, &k.LastUsedIP,
		&cidrs, &k.RevokedAt, &rateClass, &k.remindedAt); err != nil {
		return Key{}, nil, fmt.Errorf("apikeys: scan: %w", err)
	}
	k.Scopes = splitCodes(scopes)
	k.AllowedCIDRs = strings.Fields(cidrs.String)
	k.RateClass = rateClass.String
	k.CreatedAt = k.CreatedAt.UTC()
	return k, hash, nil
}

func load(ctx context.Context, tx db.Transaction, id ID) (Key, []byte, bool, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), selectKey+"WHERE id = ?"), id)
	if err != nil {
		return Key{}, nil, false, fmt.Errorf("apikeys: load: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return Key{}, nil, false, rows.Err()
	}
	k, hash, err := scanKey(rows)
	if err != nil {
		return Key{}, nil, false, err
	}
	return k, hash, true, rows.Close()
}

// Get returns one key without its secret.
func Get(ctx context.Context, tx db.Transaction, id ID) (Key, error) {
	k, _, found, err := load(ctx, tx, id)
	if err == nil && !found {
		err = ErrNotFound
	}
	return k, err
}

// List returns up to limit keys created before the key before (nil for the first page), newest first,
// revoked ones included.
func List(ctx context.Context, tx db.Transaction, before *ID, limit int) ([]Key, error) {
	q, args := selectKey, []any{}
	if before != nil {
		cursor, err := Get(ctx, tx, *before)
		if err != nil {
			return nil, err
		}
		q += "WHERE created_at < ? OR (created_at = ? AND id < ?) "
		args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
	}
	q += "ORDER BY created_at DESC, id DESC LIMIT ?"
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("apikeys: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Key{}
	for rows.Next() {
		k, _, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DueForReminder lists live keys that expire within within and had no reminder since that window
// opened (expires_at - within). The expiry job calls it per window, longest first (14 days, then 1 day),
// and MarkReminded after queueing each mail.
func DueForReminder(ctx context.Context, tx db.Transaction, within time.Duration) ([]Key, error) {
	t := now(ctx)
	q := db.Rebind(tx.Dialect(), selectKey+"WHERE revoked_at IS NULL AND expires_at > ? AND expires_at <= ? ORDER BY expires_at, id")
	rows, err := tx.Q().QueryContext(ctx, q, t, t.Add(within))
	if err != nil {
		return nil, fmt.Errorf("apikeys: due for reminder: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Key
	for rows.Next() {
		k, _, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		if k.remindedAt == nil || k.remindedAt.Before(k.ExpiresAt.Add(-within)) {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// MarkReminded records that the key's expiry reminder for the current window went out.
func MarkReminded(ctx context.Context, tx db.Transaction, id ID) error {
	q := db.Rebind(tx.Dialect(), "UPDATE api_keys SET expiry_reminded_at = ? WHERE id = ?")
	if _, err := tx.Q().ExecContext(ctx, q, now(ctx), id); err != nil {
		return fmt.Errorf("apikeys: mark reminded: %w", err)
	}
	return nil
}

func joinCodes(codes []rbac.Code) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = string(c)
	}
	return strings.Join(parts, " ")
}

func splitCodes(s string) []rbac.Code {
	out := []rbac.Code{}
	for f := range strings.FieldsSeq(s) {
		out = append(out, rbac.Code(f))
	}
	return out
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}
