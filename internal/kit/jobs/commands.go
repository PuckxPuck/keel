package jobs

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

// Opener builds the app's queue with every handler and schedule registered; done releases what it opened.
type Opener func(ctx context.Context) (q *Queue, done func(), err error)

type runFunc = func(ctx context.Context, fs *flag.FlagSet, args []string) error

// Commands are the queue and schedule commands for the app binary.
func Commands(open Opener) []cli.Command {
	work := Command(open, "queue:work", "Run job workers only (--lanes fast,slow)")
	worker := work
	worker.Name, worker.Summary = "worker", "Run job workers only; same as queue:work"
	return []cli.Command{
		work,
		worker,
		{Name: "queue:status", Summary: "Depth and oldest job per lane, kind and status", Flags: cli.JSONFlag, Run: with(open, status)},
		{Name: "queue:failed", Summary: "Failed jobs with their last error", Flags: failedFlags, Run: with(open, failed)},
		{Name: "queue:retry", Summary: "Queue a failed or cancelled job again: <id> or --all-failed", Flags: retryFlags, Run: with(open, retry)},
		{Name: "queue:cancel", Summary: "Cancel a queued or running job: <id>", Run: with(open, cancel)},
		{Name: "queue:prune", Summary: "Remove finished jobs past retention now", Run: with(open, prune)},
		{Name: "schedule:list", Summary: "Schedules with their next run times", Flags: cli.JSONFlag, Run: with(open, scheduleList)},
		{Name: "schedule:run", Summary: "Enqueue a scheduled job now: <name>", Run: with(open, scheduleRun)},
	}
}

// Command is queue:work under another name, for wiring it as the app's worker command.
func Command(open Opener, name, summary string) cli.Command {
	return cli.Command{
		Name: name, Summary: summary,
		Flags: func(fs *flag.FlagSet) {
			fs.String("lanes", "", "comma-separated lanes to run (default: all configured)")
		},
		Run: with(open, func(ctx context.Context, q *Queue, fs *flag.FlagSet, _ []string) error {
			var lanes []string
			for l := range strings.SplitSeq(fs.Lookup("lanes").Value.String(), ",") {
				if l = strings.TrimSpace(l); l != "" {
					lanes = append(lanes, l)
				}
			}
			return q.Run(ctx, lanes...)
		}),
	}
}

func with(open Opener, fn func(ctx context.Context, q *Queue, fs *flag.FlagSet, args []string) error) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		q, done, err := open(ctx)
		if err != nil {
			return err
		}
		defer done()
		return fn(ctx, q, fs, args)
	}
}

func status(ctx context.Context, q *Queue, fs *flag.FlagSet, _ []string) error {
	list, err := q.Status(ctx)
	if err != nil {
		return err
	}
	now := wallNow(ctx)
	t := cli.Table{Columns: []string{"lane", "kind", "status", "count", "oldest_age"}}
	for _, s := range list {
		t.Rows = append(t.Rows, []string{s.Lane, s.Kind, string(s.Status), strconv.FormatInt(s.Count, 10), now.Sub(s.OldestAt).Round(time.Second).String()})
	}
	return cli.Print(fs.Output(), cli.WantsJSON(fs), t)
}

func failedFlags(fs *flag.FlagSet) {
	cli.JSONFlag(fs)
	fs.Int("limit", 50, "how many to list")
}

func failed(ctx context.Context, q *Queue, fs *flag.FlagSet, _ []string) error {
	limit, err := strconv.Atoi(fs.Lookup("limit").Value.String())
	if err != nil || limit < 1 || limit > 1000 {
		return cli.Usagef("--limit must be 1 to 1000")
	}
	list, err := q.Failed(ctx, limit)
	if err != nil {
		return err
	}
	t := cli.Table{Columns: []string{"id", "kind", "attempts", "failed_at", "error_code", "error"}}
	for _, f := range list {
		t.Rows = append(t.Rows, []string{f.ID.String(), f.Kind, strconv.Itoa(f.Attempts), f.At.Format(time.RFC3339), f.ErrorCode, f.Error})
	}
	return cli.Print(fs.Output(), cli.WantsJSON(fs), t)
}

func retryFlags(fs *flag.FlagSet) { fs.Bool("all-failed", false, "retry every failed job") }

func retry(ctx context.Context, q *Queue, fs *flag.FlagSet, args []string) error {
	if fs.Lookup("all-failed").Value.String() == "true" {
		if len(args) > 0 {
			return cli.Usagef("give an id or --all-failed, not both")
		}
		n, err := q.RetryAllFailed(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "queued %d jobs again\n", n)
		return err
	}
	id, err := oneID(args)
	if err != nil {
		return err
	}
	return report(fs, q.Retry(ctx, id), "queued again")
}

func cancel(ctx context.Context, q *Queue, fs *flag.FlagSet, args []string) error {
	id, err := oneID(args)
	if err != nil {
		return err
	}
	return report(fs, q.Cancel(ctx, id), "cancelled")
}

func prune(ctx context.Context, q *Queue, fs *flag.FlagSet, _ []string) error {
	res, err := q.Prune(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(fs.Output(), "deleted %d jobs, cleared %d payloads\n", res.Deleted, res.Cleared)
	return err
}

func scheduleList(ctx context.Context, q *Queue, fs *flag.FlagSet, _ []string) error {
	list, err := q.Schedules(ctx)
	if err != nil {
		return err
	}
	t := cli.Table{Columns: []string{"name", "kind", "spec", "location", "next_run", "last_run"}}
	for _, s := range list {
		last := "never"
		if s.LastRunAt != nil {
			last = s.LastRunAt.UTC().Format(time.RFC3339)
		}
		t.Rows = append(t.Rows, []string{s.Name, s.Kind, s.Spec, s.Location, s.NextRunAt.UTC().Format(time.RFC3339), last})
	}
	return cli.Print(fs.Output(), cli.WantsJSON(fs), t)
}

func scheduleRun(ctx context.Context, q *Queue, fs *flag.FlagSet, args []string) error {
	if len(args) != 1 {
		return cli.Usagef("give one schedule name")
	}
	id, err := q.RunSchedule(ctx, args[0])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(fs.Output(), "enqueued %s\n", id)
	return err
}

func oneID(args []string) (ID, error) {
	if len(args) != 1 {
		return ID{}, cli.Usagef("give one job id")
	}
	id, err := ids.Parse[jobTag](args[0])
	if err != nil {
		return ID{}, cli.Usagef("job id is not a valid id")
	}
	return id, nil
}

func report(fs *flag.FlagSet, err error, done string) error {
	if errors.Is(err, ErrNotFound) {
		return errors.New("no job with that id")
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(fs.Output(), done)
	return err
}
