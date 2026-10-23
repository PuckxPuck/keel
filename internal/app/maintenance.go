package app

import (
	"context"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/oauthstate"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

const (
	kindAuthPrune        = "auth.prune"
	kindIdempotencyPrune = "idempotency.prune"
	kindTombstonePrune   = "paging.prune_tombstones"
)

// inboundWebhookRetention keeps received delivery ids longer than any sender retries (about three days
// for Standard Webhooks senders).
const inboundWebhookRetention = 30 * 24 * time.Hour

const tombstoneBatch = 1000

// registerMaintenance puts the retention and sweep jobs on the queue. They are global kinds and run on
// maintenanceTx: the operator pool under tenancy, so one run covers every tenant.
func (w *wiring) registerMaintenance() {
	q, run := w.queue, maintenanceTx(w.deps)
	slow := jobs.Lane(slowLane(w.cfg.Jobs))
	q.Handle(kindAuthPrune, func(ctx context.Context, _ jobs.Job) error { return w.pruneAuth(ctx, run) }, jobs.Global())
	q.Schedule(kindAuthPrune, kindAuthPrune, "7 * * * *", time.UTC)
	q.Handle(kindIdempotencyPrune, func(ctx context.Context, _ jobs.Job) error {
		return run(ctx, func(ctx context.Context, tx db.Transaction) error {
			_, err := idempotency.Prune(ctx, tx, clock.Wall(ctx).Now())
			return err
		})
	}, jobs.Global())
	q.Schedule(kindIdempotencyPrune, kindIdempotencyPrune, "27 * * * *", time.UTC)
	q.Handle(kindTombstonePrune, func(ctx context.Context, _ jobs.Job) error { return w.pruneTombstones(ctx, run) }, jobs.Global(), slow)
	q.Schedule(kindTombstonePrune, kindTombstonePrune, "37 3 * * *", time.UTC)
	w.filesMaintenance()
	w.apiKeyMaintenance()
}

// slowLane is the lane named slow when there is one, else the last, so long maintenance stays off the
// first (fast) lane.
func slowLane(cfg jobs.Config) string {
	lanes := cfg.Lanes.List()
	for _, l := range lanes {
		if l.Name == "slow" {
			return l.Name
		}
	}
	return lanes[len(lanes)-1].Name
}

// pruneAuth clears expired sign-in state: sessions, tokens, passkey challenges, OAuth states (OIDC and
// connections), received webhook ids, and the security counters.
func (w *wiring) pruneAuth(ctx context.Context, run jobs.TxRunner) error {
	now := clock.Wall(ctx).Now().UTC()
	err := run(ctx, func(ctx context.Context, tx db.Transaction) error {
		prunes := append([]func(context.Context, db.Transaction, time.Time) (int64, error){auth.Prune, tokens.Prune, oauthstate.Prune}, authPrunes()...)
		for _, prune := range prunes {
			if _, err := prune(ctx, tx, now); err != nil {
				return err
			}
		}
		_, err := webhook.Prune(ctx, tx, now.Add(-inboundWebhookRetention))
		return err
	})
	if err != nil {
		return err
	}
	_, err = ratelimit.DBStoreOf(w.db).Prune(ctx, now)
	return err
}

func (w *wiring) pruneTombstones(ctx context.Context, run jobs.TxRunner) error {
	before := clock.Wall(ctx).Now().Add(-w.cfg.Feed.TombstoneRetention)
	for {
		var n int64
		if err := run(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			n, err = paging.PruneTombstones(ctx, tx, before, tombstoneBatch)
			return err
		}); err != nil {
			return err
		}
		if n < tombstoneBatch {
			return nil
		}
	}
}
