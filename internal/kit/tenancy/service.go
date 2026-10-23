package tenancy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type Options struct {
	DB     *db.DB
	Config Config
	Audit  *audit.Recorder
	// Realm is the tenant realm: sign-ins there land in a tenant, and its roles are per tenant.
	Realm     string
	Catalogue *rbac.Catalogue
	// Templates are the built-in roles every new tenant gets; Owner is the code of the one its first user holds.
	Templates []rbac.Builtin
	Owner     string
	// AllowReadOnly names operations, by id, that a read-only tenant still serves besides those marked
	// AllowWhileReadOnly (sign-in, sign-out and the like, registered by code that does not know about tenancy).
	AllowReadOnly []string
	// AllowNonMember names operations a signed-in person who is not a member of the request's tenant may
	// still call, outside any tenant (sign-out).
	AllowNonMember []string
	// ReservedHosts are hosts no tenant's custom domain may take (the realms' and the public URL's).
	ReservedHosts []string
}

// Service is the tenancy part: one per app, made during wiring.
type Service struct {
	o     Options
	hosts *hostCache
}

// New installs the tenant transaction hooks on o.DB (Postgres only) and checks the role templates.
func New(o Options) (*Service, error) {
	switch {
	case o.DB == nil || o.Audit == nil || o.Catalogue == nil || o.Realm == "":
		return nil, errors.New("tenancy: a database, an audit recorder, the tenant realm and its catalogue are required")
	case o.DB.Dialect() != db.Postgres:
		return nil, errors.New("tenancy needs Postgres (row-level security); MySQL apps run without it")
	}
	if err := o.Config.Validate(false); err != nil {
		return nil, fmt.Errorf("tenancy: %w", err)
	}
	owner := false
	for _, b := range o.Templates {
		if unknown := o.Catalogue.Unknown(b.Permissions...); len(unknown) > 0 {
			return nil, fmt.Errorf("tenancy: role template %s uses permissions missing from the catalogue: %v", b.Code, unknown)
		}
		owner = owner || b.Code == o.Owner
	}
	if !owner {
		return nil, fmt.Errorf("tenancy: the owner role %q is not among the templates", o.Owner)
	}
	if err := Install(o.DB); err != nil {
		return nil, err
	}
	return &Service{o: o, hosts: newHostCache()}, nil
}

// New is a tenant to create.
type NewTenant struct {
	Slug    string
	Name    string
	Owner   users.ID
	Domains []string
}

const maxName = 200

type createdImage struct {
	Slug    string   `json:"slug"`
	Name    string   `json:"name"`
	Owner   users.ID `json:"owner"`
	Domains []string `json:"domains,omitempty"`
	Roles   []string `json:"roles"`
}

// Create makes a tenant with its domains, its roles copied from the templates, and its owner (a
// member holding the owner role), in one operator transaction.
func (s *Service) Create(ctx context.Context, tx db.Tx[db.Operator], in NewTenant) (Tenant, error) {
	slug, name := normaliseSlug(in.Slug), strings.TrimSpace(in.Name)
	if !ValidSlug(slug) || name == "" || utf8.RuneCountInString(name) > maxName || in.Owner.IsZero() {
		return Tenant{}, fmt.Errorf("%w: a slug (a lower-case DNS label), a name of 1 to %d characters and an owner are required", ErrInvalid, maxName)
	}
	domains := make([]string, 0, len(in.Domains))
	for _, d := range in.Domains {
		host, err := s.customDomain(d)
		if err != nil {
			return Tenant{}, err
		}
		domains = append(domains, host)
	}
	at := now(ctx)
	t := Tenant{ID: ids.NewOf[tenantTag](), Slug: slug, Name: name, Status: Active, Version: 1, CreatedAt: at, UpdatedAt: at}
	if err := insertTenant(ctx, tx, t); err != nil {
		return Tenant{}, err
	}
	for _, host := range domains {
		if err := insertDomain(ctx, tx, t.ID, host, at); err != nil {
			return Tenant{}, err
		}
	}
	roles, err := insertTemplateRoles(ctx, tx, t.ID, s.o.Realm, s.o.Templates, at)
	if err != nil {
		return Tenant{}, err
	}
	if err := AddMember(ctx, tx, t.ID, in.Owner); err != nil {
		return Tenant{}, err
	}
	if err := grantInTenant(ctx, tx, t.ID, in.Owner, roles[s.o.Owner], at); err != nil {
		return Tenant{}, err
	}
	image := createdImage{Slug: slug, Name: name, Owner: in.Owner, Domains: domains}
	for _, b := range s.o.Templates {
		image.Roles = append(image.Roles, b.Code)
	}
	tid := t.ID.UUID()
	err = s.o.Audit.Record(ctx, tx, audit.Event{Action: "tenant.created", Entity: "tenant", EntityID: t.ID.String(), After: image, Tenant: &tid})
	return t, err
}

// customDomain refuses a host that is not a host name, that sits on or under the host suffix (those
// name tenants by slug), or that a realm or the public URL serves.
func (s *Service) customDomain(raw string) (string, error) {
	host, ok := realm.Host(raw)
	if !ok || strings.Contains(host, ":") || !strings.Contains(host, ".") {
		return "", fmt.Errorf("%w: domain %q is not a host name", ErrInvalid, raw)
	}
	if suffix := s.o.Config.HostSuffix; suffix != "" && (host == suffix[1:] || strings.HasSuffix(host, suffix)) {
		return "", fmt.Errorf("%w: domain %s is under the tenant host suffix", ErrInvalid, host)
	}
	for _, r := range s.o.ReservedHosts {
		if reserved, ok := realm.Host(r); ok && reserved == host {
			return "", fmt.Errorf("%w: domain %s is served by the app itself", ErrInvalid, host)
		}
	}
	return host, nil
}

type stateImage struct {
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// SetState moves a tenant to status (the app decides when, such as billing on a failed payment) and
// audits it on the tenant's trail. Suspending ends every session working in the tenant. Only the
// operator pool writes tenants.
func (s *Service) SetState(ctx context.Context, tx db.Tx[db.Operator], id ID, status Status, reason string) (Tenant, error) {
	if !status.Valid() || utf8.RuneCountInString(reason) > maxName {
		return Tenant{}, fmt.Errorf("%w: status must be active, read_only or suspended, with a reason of at most %d characters", ErrInvalid, maxName)
	}
	before, err := oneTenant(ctx, tx, "WHERE id = $1 FOR UPDATE", id)
	if err != nil {
		return Tenant{}, err
	}
	var why *string
	if reason = strings.TrimSpace(reason); reason != "" {
		why = &reason
	}
	if err := setStatus(ctx, tx, id, status, why, now(ctx)); err != nil {
		return Tenant{}, err
	}
	if status == Suspended {
		if _, err := endSessions(ctx, tx, id); err != nil {
			return Tenant{}, err
		}
	}
	tid := id.UUID()
	if err := s.o.Audit.Record(ctx, tx, audit.Event{
		Action: "tenant.state_changed", Entity: "tenant", EntityID: id.String(), Tenant: &tid,
		Before: stateImage{Status: before.Status, Reason: before.StatusReason}, After: stateImage{Status: status, Reason: reason},
	}); err != nil {
		return Tenant{}, err
	}
	return Get(ctx, tx, id)
}

// Admit makes the service the auth.Tenancy of the tenant realm: a sign-in lands in the host's tenant,
// else the user's default membership, and needs an active membership in a tenant that is not
// suspended; anything else is auth.ErrNoAccess, answered like a wrong password.
func (s *Service) Admit(ctx context.Context, tx db.Transaction, realmName string, userID users.ID) (uuid.UUID, bool, error) {
	if realmName != s.o.Realm {
		return uuid.Nil, false, nil
	}
	if id, ok := db.TenantOf(ctx); ok {
		t, member, err := entry(ctx, tx, id, &userID)
		switch {
		case errors.Is(err, ErrNotFound):
			return uuid.Nil, true, auth.ErrNoAccess
		case err != nil:
			return uuid.Nil, true, err
		case !member || t.Status == Suspended:
			return uuid.Nil, true, auth.ErrNoAccess
		}
		return id, true, nil
	}
	id, found, err := landing(ctx, tx, userID)
	if err == nil && !found {
		err = auth.ErrNoAccess
	}
	return id, true, err
}

var _ auth.Tenancy = (*Service)(nil)

// Enter checks that user may switch into tenant: an active membership in a tenant that is not
// suspended. It returns the tenant for WithTenant.
func (s *Service) Enter(ctx context.Context, tx db.Transaction, id ID, user users.ID) (Tenant, error) {
	t, member, err := entry(ctx, tx, id.UUID(), &user)
	switch {
	case errors.Is(err, ErrNotFound), err == nil && !member:
		return Tenant{}, ErrNotAMember
	case err != nil:
		return Tenant{}, err
	case t.Status == Suspended:
		return Tenant{}, ErrSuspended
	}
	return t, nil
}

func (s *Service) allowedReadOnly(id string) bool { return slices.Contains(s.o.AllowReadOnly, id) }

func (s *Service) allowedNonMember(id string) bool { return slices.Contains(s.o.AllowNonMember, id) }

func wallNow(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}
