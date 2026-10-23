package files

import (
	"context"
	"errors"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

type SweepOptions struct {
	// MinAge skips objects younger than this (default 24h), and temporary files of local storage.
	MinAge time.Duration
	// TTL is how long a pending or staged file may wait to be attached (default 24h).
	TTL time.Duration
	// Batch is how many keys or rows one round handles (default 500).
	Batch int
}

type SweepResult struct {
	Orphans int
	Expired int
}

// Sweep removes pending and staged files nobody attached, then objects under the service's key prefix
// that have no row: objects whose delete failed after their row went. A row is always written before
// its object, so an object without a row is never one still being uploaded. It works in batches over a
// streamed listing, so memory stays flat.
func (s *Service) Sweep(ctx context.Context, opts SweepOptions) (SweepResult, error) {
	if opts.MinAge <= 0 {
		opts.MinAge = 24 * time.Hour
	}
	if opts.TTL <= 0 {
		opts.TTL = 24 * time.Hour
	}
	if opts.Batch <= 0 {
		opts.Batch = 500
	}
	now := clock.Wall(ctx).Now()
	var res SweepResult
	var err error
	if res.Expired, err = s.sweepExpired(ctx, now.Add(-opts.TTL), opts.Batch); err != nil {
		return res, err
	}
	if res.Orphans, err = s.sweepOrphans(ctx, now.Add(-opts.MinAge), opts.Batch); err != nil {
		return res, err
	}
	if l, ok := s.opts.Storage.(*Local); ok {
		err = l.PruneTemp(ctx, now.Add(-opts.MinAge))
	}
	return res, err
}

func (s *Service) sweepExpired(ctx context.Context, before time.Time, batch int) (int, error) {
	total := 0
	for {
		var taken []expired
		err := s.opts.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			taken, err = takeExpired(ctx, tx, before, batch)
			return err
		})
		if err != nil {
			return total, err
		}
		for _, e := range taken {
			// a failed delete leaves an orphan for the next sweep
			if err := s.opts.Storage.Delete(ctx, e.key); err != nil {
				return total, err
			}
		}
		total += len(taken)
		if len(taken) < batch {
			return total, nil
		}
	}
}

func (s *Service) sweepOrphans(ctx context.Context, before time.Time, batch int) (int, error) {
	total := 0
	keys := make([]string, 0, batch)
	flush := func() error {
		if len(keys) == 0 {
			return nil
		}
		var known map[string]bool
		err := s.opts.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			known, err = knownKeys(ctx, tx, keys)
			return err
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if known[k] {
				continue
			}
			if err := s.opts.Storage.Delete(ctx, k); err != nil {
				return err
			}
			total++
		}
		keys = keys[:0]
		return nil
	}
	err := s.opts.Storage.List(ctx, s.opts.KeyPrefix+objectDir, func(o ObjectInfo) error {
		if _, own := keyTenant(s.opts.KeyPrefix, o.Key); !o.ModTime.Before(before) || !own {
			return nil
		}
		keys = append(keys, o.Key)
		if len(keys) < batch {
			return nil
		}
		return flush()
	})
	return total, errors.Join(err, flush())
}
