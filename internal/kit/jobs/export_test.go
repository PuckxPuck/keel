package jobs

import "context"

var (
	ErrLeaseLost = errLeaseLost
	BackoffDelay = backoff
)

func (q *Queue) TickSchedules(ctx context.Context) error { return q.tickSchedules(ctx) }

func (q *Queue) SyncSchedules(ctx context.Context) error { return q.syncSchedules(ctx) }
