package rbac

import (
	"errors"
	"net/http"
	"slices"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

// Policy names the permission that manages access. Access refuses changes that would leave a realm
// without an active user holding it everywhere, or without a role carrying it.
type Policy struct {
	AccessManage Code
}

const (
	RuleOwnRoles          = "own_roles"
	RuleExceedsActor      = "grant_exceeds_actor"
	RuleLastAccessUser    = "last_access_holder"
	RuleLastAccessRole    = "last_access_role"
	RuleUnknownPermission = "unknown_permission"
	RuleInvalidRoleCode   = "invalid_role_code"
	RuleInvalidRoleName   = "invalid_role_name"
	CodeRoleExists        = "role_exists"
	CodeChecksFailed      = "checks_failed"
	CodeAlreadyGranted    = "already_granted"
	CodeBuiltinRole       = "builtin_role"
	checksFailedMessage   = "the change breaks access rules"
)

type Violation struct {
	Rule        string `json:"rule"`
	Permissions []Code `json:"permissions,omitempty"`
}

// RefusedError carries every violation, for a 422 checks_failed answer.
type RefusedError struct {
	Violations []Violation
}

func (e *RefusedError) Error() string { return checksFailedMessage }

// Refuse is nil when there are no violations.
func Refuse(v []Violation) error {
	if len(v) == 0 {
		return nil
	}
	return &RefusedError{Violations: v}
}

var (
	ErrRoleNotFound   = errors.New("role not found")
	ErrGrantNotFound  = errors.New("role grant not found")
	ErrAlreadyGranted = errors.New("role is already granted")
	ErrRoleExists     = errors.New("a role with this code already exists")
	ErrUserDisabled   = errors.New("user is disabled")
	// ErrBuiltinRole is a change to a built-in role, which only the app's definition (and setup) changes.
	ErrBuiltinRole = errors.New("built-in roles cannot be changed or deleted; create a custom role instead")
	// ErrForbidden is an actor without the access-management permission where the change applies.
	ErrForbidden = errors.New("you do not have permission to manage this access")
)

// Mapper answers a RefusedError with 422 checks_failed and the broken rules in checks, and maps the
// package's other errors.
func Mapper(err error) (*problem.Problem, bool) {
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		p := problem.New(http.StatusUnprocessableEntity, CodeChecksFailed, checksFailedMessage)
		p.Extensions = map[string]any{"checks": refused.Violations}
		return p, true
	case errors.Is(err, ErrRoleNotFound), errors.Is(err, ErrGrantNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, err.Error()), true
	case errors.Is(err, ErrAlreadyGranted):
		return problem.New(http.StatusConflict, CodeAlreadyGranted, err.Error()), true
	case errors.Is(err, ErrRoleExists):
		return problem.New(http.StatusConflict, CodeRoleExists, err.Error()), true
	case errors.Is(err, ErrBuiltinRole):
		return problem.New(http.StatusUnprocessableEntity, CodeBuiltinRole, err.Error()), true
	case errors.Is(err, ErrForbidden):
		return problem.New(http.StatusForbidden, problem.CodeForbidden, "you do not have permission to do this"), true
	}
	return nil, false
}

// lacking lists the catalogue permissions in perms the actor does not hold where the grant applies.
func lacking(actor Principal, cat *Catalogue, perms []Code, scope *Scope) []Code {
	var out []Code
	for _, perm := range perms {
		if !cat.Has(perm) || slices.Contains(out, perm) {
			continue
		}
		held := actor.Can(perm) || (scope != nil && actor.CanIn(perm, *scope))
		if !held {
			out = append(out, perm)
		}
	}
	return out
}

// mayManage is true when actor may change access where scope applies (nil: everywhere).
func mayManage(actor Principal, manage Code, scope *Scope) bool {
	if actor.system {
		return true
	}
	return actor.Can(manage) || (scope != nil && actor.CanIn(manage, *scope))
}
