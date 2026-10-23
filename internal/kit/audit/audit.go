// Package audit writes the append-only audit log in the caller's transaction.
package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorSystem ActorType = "system"
	ActorAPIKey ActorType = "apikey"
	ActorDevice ActorType = "device"
)

// Actor is who acted. OnBehalfOf is the person behind an API key, a device, or an operator's "view as".
type Actor struct {
	Type       ActorType
	ID         *uuid.UUID
	OnBehalfOf *uuid.UUID
}

type actorKey struct{}

// WithActor sets the actor for every Record in ctx; the session resolver sets it per request.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom is the context's actor, or the system when none is set (CLI, jobs).
func ActorFrom(ctx context.Context) Actor {
	if a, ok := ctx.Value(actorKey{}).(Actor); ok {
		return a
	}
	return Actor{Type: ActorSystem}
}

// Event is one change. Before and After are values (usually structs) marshalled to JSON with fields
// tagged `audit:"redact"` replaced and `audit:"-"` dropped; nil leaves the column null.
type Event struct {
	Action   string
	Entity   string
	EntityID string
	Before   any
	After    any
	// Tenant names the tenant an operator acted on; otherwise the row takes the context's tenant.
	Tenant *uuid.UUID
}

type Options struct {
	// Chain links every row to the previous one by hash, serialising audit writes on the chain's head
	// row (tamper evidence).
	Chain bool
}

type Recorder struct {
	chain bool
}

func New(opts Options) *Recorder { return &Recorder{chain: opts.Chain} }

const (
	maxAction   = 64
	maxEntity   = 64
	maxEntityID = 128
	// GlobalChain holds the rows without a tenant; under tenancy each tenant's rows chain on their own
	// head, keyed by the tenant id.
	GlobalChain = "global"
)

var ErrInvalidEvent = errors.New("audit: invalid event")

// Record writes ev in tx, so it commits or rolls back with the change it describes.
func (r *Recorder) Record(ctx context.Context, tx db.Transaction, ev Event) error {
	if ev.Action == "" || utf8.RuneCountInString(ev.Action) > maxAction ||
		utf8.RuneCountInString(ev.Entity) > maxEntity || utf8.RuneCountInString(ev.EntityID) > maxEntityID {
		return fmt.Errorf("%w: action is required; action and entity up to %d characters, entity id up to %d",
			ErrInvalidEvent, maxAction, maxEntityID)
	}
	row, err := r.newRow(ctx, ev)
	if err != nil {
		return err
	}
	if tx.Tenancy() {
		row.tenancy, row.tenant = true, ev.Tenant
		if row.tenant == nil {
			if id, ok := db.TenantOf(ctx); ok {
				row.tenant = &id
			}
		}
	}
	if !r.chain {
		return insert(ctx, tx, row)
	}
	key := chainKey(row.tenant)
	if row.prevHash, err = lockHead(ctx, tx, key, row); err != nil {
		return err
	}
	if row.hash, err = row.chainHash(); err != nil {
		return err
	}
	if err := insert(ctx, tx, row); err != nil {
		return err
	}
	return moveHead(ctx, tx, key, row)
}

func chainKey(tenant *uuid.UUID) string {
	if tenant == nil {
		return GlobalChain
	}
	return tenant.String()
}

func (r *Recorder) newRow(ctx context.Context, ev Event) (row, error) {
	before, err := marshal(ev.Before)
	if err != nil {
		return row{}, fmt.Errorf("audit %s before: %w", ev.Action, err)
	}
	after, err := marshal(ev.After)
	if err != nil {
		return row{}, fmt.Errorf("audit %s after: %w", ev.Action, err)
	}
	actor := ActorFrom(ctx)
	out := row{
		id:         ids.New(),
		occurredAt: clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond),
		realm:      optional(httpx.Realm(ctx)),
		actorType:  actor.Type,
		actorID:    actor.ID,
		onBehalfOf: actor.OnBehalfOf,
		action:     ev.Action,
		entity:     ev.Entity,
		entityID:   ev.EntityID,
		before:     before,
		after:      after,
		requestID:  optional(problem.RequestID(ctx)),
	}
	if ip := httpx.ClientIP(ctx); ip.IsValid() {
		out.ip = optional(ip.String())
	}
	return out, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
