package clock

import (
	"context"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/dates"
)

type Clock interface{ Now() time.Time }

type ctxKey int

const (
	wallKey ctxKey = iota
	businessKey
)

type system struct{}

func (system) Now() time.Time { return time.Now().UTC() }

type fixed struct{ t time.Time }

func (f fixed) Now() time.Time { return f.t }

type offset struct {
	base Clock
	d    time.Duration
}

func (o offset) Now() time.Time { return o.base.Now().Add(o.d) }

func Fixed(t time.Time) Clock { return fixed{t: t.UTC()} }

// Wall is real time for expiry, leases and signatures; only WithWall changes it.
func Wall(ctx context.Context) Clock {
	if c, ok := ctx.Value(wallKey).(Clock); ok {
		return c
	}
	return system{}
}

// Business is domain time: real unless a test or demo pinned or shifted it.
func Business(ctx context.Context) Clock {
	if c, ok := ctx.Value(businessKey).(Clock); ok {
		return c
	}
	return system{}
}

func WithFixed(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, businessKey, Clock(Fixed(t)))
}

func WithOffset(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, businessKey, Clock(offset{base: Business(ctx), d: d}))
}

// WithWall is a test helper; production code never replaces the wall clock.
func WithWall(ctx context.Context, c Clock) context.Context {
	return context.WithValue(ctx, wallKey, c)
}

func Today(ctx context.Context, loc *time.Location) dates.Date {
	return dates.FromTime(Business(ctx).Now().In(loc))
}
