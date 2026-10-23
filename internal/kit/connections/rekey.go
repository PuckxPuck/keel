package connections

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

// RekeyResult counts the token values Rekey rewrapped and those no configured key opens.
type RekeyResult struct {
	Rewrapped  int
	Unreadable int
}

const rekeyBatch = 100

// Rekey reseals every stored token that an older key opened with the newest key, in batches, so the
// older key can then be removed. The plaintext does not change, so neither does the version.
func (s *Service) Rekey(ctx context.Context) (RekeyResult, error) {
	var total RekeyResult
	after := "00000000-0000-0000-0000-000000000000"
	for {
		var batch RekeyResult
		var n int
		var last string
		err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			batch, n, last = RekeyResult{}, 0, after
			rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(),
				"SELECT id, access_token, refresh_token FROM connections WHERE id > ? ORDER BY id LIMIT ? FOR UPDATE"), after, rekeyBatch)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			type row struct {
				id              ID
				access, refresh []byte
			}
			var list []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.access, &r.refresh); err != nil {
					return err
				}
				list = append(list, r)
			}
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return err
			}
			for _, r := range list {
				n, last = n+1, r.id.String()
				for _, v := range []struct {
					column, field string
					sealed        []byte
				}{{"access_token", "access", r.access}, {"refresh_token", "refresh", r.refresh}} {
					if v.sealed == nil {
						continue
					}
					bound := aad(r.id, v.field)
					plain, stale, err := s.keys.Open(v.sealed, bound)
					switch {
					case err != nil:
						batch.Unreadable++
					case stale:
						if _, err := exec(ctx, tx, "UPDATE connections SET "+v.column+" = ? WHERE id = ?", s.keys.Seal(plain, bound), r.id); err != nil {
							return err
						}
						batch.Rewrapped++
					}
				}
			}
			return nil
		})
		if err != nil {
			return total, fmt.Errorf("connections: rekey: %w", err)
		}
		total.Rewrapped += batch.Rewrapped
		total.Unreadable += batch.Unreadable
		if n < rekeyBatch {
			return total, nil
		}
		after = last
	}
}

// Opener builds the app's connections service; done releases what it opened.
type Opener func(ctx context.Context) (s *Service, done func(), err error)

// Commands are the connection maintenance commands for the app binary.
func Commands(open Opener) []cli.Command {
	return []cli.Command{{
		Name: "connection:rekey", Summary: "Reseal stored provider tokens with the newest key, so older keys can be removed",
		Run: func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
			s, done, err := open(ctx)
			if err != nil {
				return err
			}
			defer done()
			res, err := s.Rekey(ctx)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(fs.Output(), "resealed %d tokens; %d could not be opened\n", res.Rewrapped, res.Unreadable); err != nil {
				return err
			}
			if res.Unreadable > 0 {
				return errors.New("some tokens open with no configured key; keep the old keys until those connections are authorised again")
			}
			return nil
		},
	}}
}
