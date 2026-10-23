package rbac

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/users"
)

// Scope narrows a grant to one thing, such as one branch or one department.
type Scope struct {
	Type string    `json:"type"`
	ID   uuid.UUID `json:"id"`
}

// Grant is one permission, everywhere (nil Scope) or within a scope.
type Grant struct {
	Perm  Code
	Scope *Scope
}

// SubjectKind is what a principal is: a person, an API key or a shared device.
type SubjectKind string

const (
	SubjectUser   SubjectKind = "user"
	SubjectAPIKey SubjectKind = "apikey"
	SubjectDevice SubjectKind = "device"
)

// Principal is who is calling in a realm and what they may do; the union of their roles. UserID is set
// for people; keys and devices carry their own id as Subject and may act on behalf of a person.
type Principal struct {
	UserID     users.ID
	Realm      string
	kind       SubjectKind
	subject    uuid.UUID
	onBehalfOf *users.ID
	tenant     *uuid.UUID
	system     bool
	global     map[Code]bool
	scoped     map[Code][]Scope
}

// System is the break-glass actor of shell commands such as user:grant. Access changes skip the
// checks of what the actor holds, never the realm check or the last-holder rules. Request paths never use it.
func System(realm string) Principal {
	return Principal{Realm: realm, system: true, global: map[Code]bool{}, scoped: map[Code][]Scope{}}
}

func (p Principal) IsSystem() bool { return p.system }

// ActingUser makes a Principal a users.Actor: the person, or the person a key or device acts for.
func (p Principal) ActingUser() (users.ID, bool) {
	switch {
	case p.system:
		return users.ID{}, false
	case p.Kind() == SubjectUser:
		return p.UserID, !p.UserID.IsZero()
	case p.onBehalfOf != nil:
		return *p.onBehalfOf, true
	}
	return users.ID{}, false
}

// Kind is SubjectUser unless the principal was made with NewSubject.
func (p Principal) Kind() SubjectKind {
	if p.kind == "" {
		return SubjectUser
	}
	return p.kind
}

// Subject is the id of the user, key or device.
func (p Principal) Subject() uuid.UUID {
	if p.Kind() == SubjectUser {
		return p.UserID.UUID()
	}
	return p.subject
}

// Key names the principal for rate limits and idempotency keys: kind and id.
func (p Principal) Key() string {
	switch p.Kind() {
	case SubjectAPIKey:
		return "k:" + p.subject.String()
	case SubjectDevice:
		return "d:" + p.subject.String()
	case SubjectUser:
	}
	return "u:" + p.UserID.String()
}

// OnBehalfOf is the person a key or device acts for, when one signed in on top of it.
func (p Principal) OnBehalfOf() (users.ID, bool) {
	if p.onBehalfOf == nil {
		return users.ID{}, false
	}
	return *p.onBehalfOf, true
}

// InTenant returns p acting for a tenant: an API key's or a device's tenant under tenancy.
func (p Principal) InTenant(id uuid.UUID) Principal {
	p.tenant = &id
	return p
}

// Tenant is the tenant a key or device principal acts for.
func (p Principal) Tenant() (uuid.UUID, bool) {
	if p.tenant == nil {
		return uuid.UUID{}, false
	}
	return *p.tenant, true
}

// ActingFor returns p acting on behalf of user.
func (p Principal) ActingFor(user users.ID) Principal {
	p.onBehalfOf = &user
	return p
}

func (p Principal) valid() bool {
	if p.system {
		return false
	}
	if p.Kind() == SubjectUser {
		return !p.UserID.IsZero()
	}
	return p.subject != uuid.Nil
}

func NewPrincipal(userID users.ID, realm string, grants ...Grant) Principal {
	return newPrincipal(Principal{UserID: userID, Realm: realm, kind: SubjectUser}, grants)
}

// NewSubject is the principal of an API key or a device; it holds only the grants given here.
func NewSubject(kind SubjectKind, id uuid.UUID, realm string, grants ...Grant) Principal {
	if kind == SubjectUser || kind == "" {
		panic("rbac: NewSubject is for keys and devices; use NewPrincipal for people")
	}
	return newPrincipal(Principal{Realm: realm, kind: kind, subject: id}, grants)
}

func newPrincipal(p Principal, grants []Grant) Principal {
	p.global, p.scoped = map[Code]bool{}, map[Code][]Scope{}
	for _, g := range grants {
		if g.Scope == nil {
			p.global[g.Perm] = true
			continue
		}
		if !slices.Contains(p.scoped[g.Perm], *g.Scope) {
			p.scoped[g.Perm] = append(p.scoped[g.Perm], *g.Scope)
		}
	}
	return p
}

// Can is true when the permission is held everywhere.
func (p Principal) Can(code Code) bool { return p.global[code] }

// CanIn is true when the permission is held everywhere or within scope.
func (p Principal) CanIn(code Code, scope Scope) bool {
	return p.global[code] || slices.Contains(p.scoped[code], scope)
}

// Missing lists the codes not held everywhere.
func (p Principal) Missing(codes ...Code) []Code {
	var out []Code
	for _, c := range codes {
		if !p.global[c] {
			out = append(out, c)
		}
	}
	return out
}

// Permissions lists every code held anywhere, sorted.
func (p Principal) Permissions() []Code {
	out := make([]Code, 0, len(p.global)+len(p.scoped))
	for c := range p.global {
		out = append(out, c)
	}
	for c := range p.scoped {
		if !p.global[c] {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Code) int { return strings.Compare(string(a), string(b)) })
	return out
}

// Principals finds the caller; the session resolver provides it.
type Principals interface {
	Principal(ctx context.Context) (Principal, bool)
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext reads the principal WithPrincipal stored.
type FromContext struct{}

func (FromContext) Principal(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.valid()
}
