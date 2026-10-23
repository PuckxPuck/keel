package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/adhocore/gronx"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

func nextSlot(spec string, loc *time.Location, after time.Time) (time.Time, error) {
	next, err := gronx.NextTickAfter(spec, after.In(loc), false)
	if err != nil {
		return time.Time{}, fmt.Errorf("next slot of %q: %w", spec, err)
	}
	return next.UTC().Truncate(time.Microsecond), nil
}

func (q *Queue) scheduleNames() []string {
	return slices.Sorted(maps.Keys(q.schedules))
}

// syncSchedules makes the rows match the code: missing rows are added and a changed spec, location or
// kind moves the next slot.
func (q *Queue) syncSchedules(ctx context.Context) error {
	for _, name := range q.scheduleNames() {
		s := q.schedules[name]
		err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			now := wallNow(ctx)
			next, err := nextSlot(s.spec, s.loc, now)
			if err != nil {
				return err
			}
			insert := "INSERT INTO job_schedules (name, kind, spec, location, next_run_at, build, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
			if tx.Dialect() == db.MySQL {
				insert += "ON DUPLICATE KEY UPDATE name = name"
			} else {
				insert += "ON CONFLICT (name) DO NOTHING"
			}
			if _, err := exec(ctx, tx, insert, s.name, s.kind, s.spec, s.loc.String(), next, q.build, now, now); err != nil {
				return err
			}
			var kind, spec, location string
			var build sql.NullString
			if err := scanOne(ctx, tx, "SELECT kind, spec, location, build FROM job_schedules WHERE name = ? FOR UPDATE",
				[]any{s.name}, &kind, &spec, &location, &build); err != nil {
				return err
			}
			if (kind == s.kind && spec == s.spec && location == s.loc.String()) || q.build < build.String {
				return nil
			}
			_, err = exec(ctx, tx, "UPDATE job_schedules SET kind = ?, spec = ?, location = ?, next_run_at = ?, build = ?, updated_at = ? WHERE name = ?",
				s.kind, s.spec, s.loc.String(), next, q.build, now, s.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("jobs: sync schedule %s: %w", name, err)
		}
	}
	return nil
}

// tickSchedules enqueues every due schedule once. The row lock makes concurrent ticks skip a schedule
// another process is enqueueing, and the slot's unique key backs that up.
func (q *Queue) tickSchedules(ctx context.Context) error {
	names := q.scheduleNames()
	if len(names) == 0 {
		return nil
	}
	return q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		now := wallNow(ctx)
		args := []any{now}
		marks := ""
		for i, n := range names {
			if i > 0 {
				marks += ", "
			}
			marks += "?"
			args = append(args, n)
		}
		rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(),
			"SELECT name, next_run_at, spec, location FROM job_schedules WHERE next_run_at <= ? AND name IN ("+marks+") ORDER BY next_run_at FOR UPDATE SKIP LOCKED"), args...)
		if err != nil {
			return err
		}
		list, err := scanDue(rows)
		if err != nil {
			return err
		}
		for _, d := range list {
			s := q.schedules[d.name]
			if loc, err := time.LoadLocation(d.location); err == nil && gronx.IsValid(d.spec) {
				s.spec, s.loc = d.spec, loc
			}
			if err := q.fire(ctx, tx, s, d.slot, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// due carries the stored spec, which a newer build may have written: every process follows it.
type due struct {
	name     string
	slot     time.Time
	spec     string
	location string
}

func scanDue(rows *sql.Rows) ([]due, error) {
	defer func() { _ = rows.Close() }()
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.name, &d.slot, &d.spec, &d.location); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, errors.Join(rows.Err(), rows.Close())
}

func (q *Queue) fire(ctx context.Context, tx db.Transaction, s schedule, slot, now time.Time) error {
	id, err := q.Enqueue(ctx, tx, s.kind, nil, Unique("schedule:"+s.name+":"+strconv.FormatInt(slot.Unix(), 10)))
	if err != nil {
		return fmt.Errorf("schedule %s: %w", s.name, err)
	}
	next, err := nextSlot(s.spec, s.loc, now)
	if err != nil {
		return err
	}
	_, err = exec(ctx, tx, "UPDATE job_schedules SET next_run_at = ?, last_run_at = ?, last_job_id = ?, updated_at = ? WHERE name = ?",
		next, slot, id, now, s.name)
	return err
}

// ScheduleInfo is one schedule as stored.
type ScheduleInfo struct {
	Name      string
	Kind      string
	Spec      string
	Location  string
	NextRunAt time.Time
	LastRunAt *time.Time
}

// Schedules lists the schedules registered in code with their stored state; a schedule not yet synced
// shows its next slot from now.
func (q *Queue) Schedules(ctx context.Context) ([]ScheduleInfo, error) {
	out := make([]ScheduleInfo, 0, len(q.schedules))
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		out = out[:0]
		for _, name := range q.scheduleNames() {
			s := q.schedules[name]
			info := ScheduleInfo{Name: s.name, Kind: s.kind, Spec: s.spec, Location: s.loc.String()}
			var last sql.NullTime
			err := scanOne(ctx, tx, "SELECT next_run_at, last_run_at FROM job_schedules WHERE name = ?", []any{name}, &info.NextRunAt, &last)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if info.NextRunAt, err = nextSlot(s.spec, s.loc, wallNow(ctx)); err != nil {
					return err
				}
			case err != nil:
				return err
			}
			if last.Valid {
				info.LastRunAt = &last.Time
			}
			out = append(out, info)
		}
		return nil
	})
	return out, err
}

// RunSchedule enqueues a schedule's kind now, outside its slots.
func (q *Queue) RunSchedule(ctx context.Context, name string) (ID, error) {
	s, ok := q.schedules[name]
	if !ok {
		return ID{}, fmt.Errorf("jobs: no schedule named %q", name)
	}
	var id ID
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		id, err = q.Enqueue(ctx, tx, s.kind, nil)
		return err
	})
	return id, err
}
