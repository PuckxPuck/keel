package webhooks

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

// Opener builds the app's webhook service; done releases what it opened.
type Opener func(ctx context.Context) (s *Service, done func(), err error)

// Commands are the outbound webhook troubleshooting commands for the app binary.
func Commands(open Opener) []cli.Command {
	return []cli.Command{
		{
			Name: "webhook:deliveries", Summary: "Latest outbound webhook deliveries", Run: with(open, deliveries),
			Flags: func(fs *flag.FlagSet) {
				cli.JSONFlag(fs)
				fs.Int("limit", 50, "how many to list")
			},
		},
		{Name: "webhook:replay", Summary: "Send a delivery's event to its endpoint again: <delivery id>", Run: with(open, replay)},
		{Name: "webhook:rekey", Summary: "Reseal endpoint secrets with the newest key, so older keys can be removed", Run: with(open, rekey)},
	}
}

func with(open Opener, fn func(ctx context.Context, s *Service, fs *flag.FlagSet, args []string) error) func(context.Context, *flag.FlagSet, []string) error {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		s, done, err := open(ctx)
		if err != nil {
			return err
		}
		defer done()
		return fn(ctx, s, fs, args)
	}
}

func deliveries(ctx context.Context, s *Service, fs *flag.FlagSet, _ []string) error {
	limit, err := strconv.Atoi(fs.Lookup("limit").Value.String())
	if err != nil || limit < 1 || limit > 1000 {
		return cli.Usagef("--limit must be 1 to 1000")
	}
	var list []Delivery
	err = s.o.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		list, err = s.Deliveries(ctx, tx, limit)
		return err
	})
	if err != nil {
		return err
	}
	t := cli.Table{Columns: []string{"id", "event", "endpoint", "status", "attempts", "http_status", "error_code", "created_at"}}
	for _, d := range list {
		httpStatus, code := "", ""
		if d.LastStatusCode != nil {
			httpStatus = strconv.Itoa(*d.LastStatusCode)
		}
		if d.LastErrorCode != nil {
			code = *d.LastErrorCode
		}
		t.Rows = append(t.Rows, []string{
			d.ID.String(), d.EventType, d.EndpointID.String(), string(d.Status), strconv.Itoa(d.Attempts),
			httpStatus, code, d.CreatedAt.Format(time.RFC3339),
		})
	}
	return cli.Print(fs.Output(), cli.WantsJSON(fs), t)
}

func replay(ctx context.Context, s *Service, fs *flag.FlagSet, args []string) error {
	if len(args) != 1 {
		return cli.Usagef("give one delivery id")
	}
	id, err := ids.Parse[deliveryTag](args[0])
	if err != nil {
		return cli.Usagef("delivery id is not a valid id")
	}
	var next DeliveryID
	err = s.o.Tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		next, err = s.Replay(ctx, tx, id)
		return err
	})
	if errors.Is(err, ErrDeliveryMissing) {
		return errors.New("no delivery with that id")
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(fs.Output(), "queued delivery %s\n", next)
	return err
}

func rekey(ctx context.Context, s *Service, fs *flag.FlagSet, _ []string) error {
	res, err := s.Rekey(ctx)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(fs.Output(), "resealed %d secrets; %d could not be opened\n", res.Rewrapped, res.Unreadable); err != nil {
		return err
	}
	if res.Unreadable > 0 {
		return errors.New("some secrets open with no configured key; keep the old keys until those endpoints get new secrets")
	}
	return nil
}
