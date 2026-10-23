package users

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
)

const entity = "user"

// Actor is who makes a change; rbac.Principal is one. The system (shell commands) has no user.
type Actor interface {
	ActingUser() (ID, bool)
}

// Guard checks a status change inside its transaction before the user is read or written; rbac.Access
// is the guard apps wire, keeping the last access manager from being disabled.
type Guard interface {
	CheckStatus(ctx context.Context, tx db.Transaction, actor Actor, target ID, to Status) error
}

type Service struct {
	audit *audit.Recorder
	guard Guard
}

// NewService panics without a guard: status changes are never unguarded.
func NewService(rec *audit.Recorder, guard Guard) *Service {
	if rec == nil || guard == nil {
		panic("users: NewService needs a recorder and a guard")
	}
	return &Service{audit: rec, guard: guard}
}

type NewUser struct {
	Email string
	Name  string
}

func (s *Service) Create(ctx context.Context, tx db.Transaction, in NewUser) (User, error) {
	email, err := NormaliseEmail(in.Email)
	if err != nil {
		return User{}, err
	}
	name := strings.TrimSpace(in.Name)
	if utf8.RuneCountInString(name) > maxName {
		return User{}, ErrInvalidName
	}
	now := clock.Business(ctx).Now().UTC().Truncate(time.Microsecond)
	u := User{ID: ids.NewOf[userTag](), Email: email, Name: name, Status: Active, CreatedAt: now, UpdatedAt: now, Version: 1}
	if err := insert(ctx, tx, u); err != nil {
		return User{}, err
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "user.created", Entity: entity, EntityID: u.ID.String(), After: u}); err != nil {
		return User{}, err
	}
	return u, nil
}

// SetStatus enables or disables a user at the version the caller read; a stale version is an
// occ.StaleError, and the guard may refuse the change.
func (s *Service) SetStatus(ctx context.Context, tx db.Transaction, actor Actor, id ID, version int, status Status) (User, error) {
	if !status.Valid() {
		return User{}, fmt.Errorf("users: unknown status %q", status)
	}
	if actor == nil {
		return User{}, fmt.Errorf("users: SetStatus needs an actor")
	}
	if err := s.guard.CheckStatus(ctx, tx, actor, id, status); err != nil {
		return User{}, err
	}
	before, err := getForUpdate(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	var by *ID
	if who, ok := actor.ActingUser(); ok {
		by = &who
	}
	res, err := setStatus(ctx, tx, id, version, status, by, clock.Business(ctx).Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return User{}, fmt.Errorf("set user status: %w", err)
	}
	if err := occ.Check(ctx, res, current(tx, id)); err != nil {
		return User{}, err
	}
	if err := BumpAccess(ctx, tx, id); err != nil {
		return User{}, err
	}
	after, err := Get(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	action := "user.enabled"
	if status == Disabled {
		action = "user.disabled"
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: action, Entity: entity, EntityID: id.String(), Before: before, After: after}); err != nil {
		return User{}, err
	}
	return after, nil
}
