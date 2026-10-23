package apikeys

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

// Leak is one report from a secret-scanning partner, shaped on GitHub's partner alerts: the token
// found, its type, and where it was found.
type Leak struct {
	Token  string `json:"token" maxLength:"256"`
	Type   string `json:"type,omitempty" maxLength:"100"`
	URL    string `json:"url,omitempty" maxLength:"2048"`
	Source string `json:"source,omitempty" maxLength:"100"`
}

// Label is the answer for one reported token.
type Label string

const (
	TruePositive  Label = "true_positive"
	FalsePositive Label = "false_positive"
	// MaxLeaks bounds one report.
	MaxLeaks = 100
)

type LeakResult struct {
	TokenHash string `json:"tokenHash" doc:"SHA-256 of the reported token, hex"`
	Label     Label  `json:"label" enum:"true_positive,false_positive"`
}

type leakImage struct {
	URL    string `json:"url,omitempty"`
	Source string `json:"source,omitempty"`
}

// ReportLeaks answers which reported tokens are this app's keys (a true positive even when already
// revoked) and, unless the delivery is a replay, revokes them, all in tx. The caller records the
// delivery id with webhook.Verifier.Seen in tx and passes what it answered as replayed. The report that
// revokes a key records apikey.leaked and runs OnLeak; a report of a key already revoked records
// apikey.leak_reported and runs nothing, so a partner retrying or racing itself alerts once.
func (s *Service) ReportLeaks(ctx context.Context, tx db.Transaction, reports []Leak, replayed bool) ([]LeakResult, error) {
	if len(reports) > MaxLeaks {
		return nil, ErrInvalidInput
	}
	out := make([]LeakResult, 0, len(reports))
	for _, r := range reports {
		sum := sha256.Sum256([]byte(r.Token))
		res := LeakResult{TokenHash: hex.EncodeToString(sum[:]), Label: FalsePositive}
		k, ok, err := s.match(ctx, tx, r.Token)
		if err != nil {
			return nil, err
		}
		if ok {
			res.Label = TruePositive
		}
		if ok && !replayed {
			if err := s.leaked(ctx, tx, k, r); err != nil {
				return nil, err
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *Service) match(ctx context.Context, tx db.Transaction, token string) (Key, bool, error) {
	id, hash, err := s.format.Parse(token)
	if err != nil {
		return Key{}, false, nil //nolint:nilerr // a token that is not one of ours is a false positive, not a failure
	}
	k, stored, found, err := load(ctx, tx, ids.FromUUID[keyTag](id))
	if err != nil || !found {
		return Key{}, false, err
	}
	return k, subtle.ConstantTimeCompare(hash, stored) == 1, nil
}

// leaked revokes k; the conditional update makes exactly one report win, even against a concurrent one.
// Under tenancy the report runs on the operator pool, and what it records and runs is the key's tenant's.
func (s *Service) leaked(ctx context.Context, tx db.Transaction, k Key, r Leak) error {
	if tx.Tenancy() {
		tenant, err := keyTenant(ctx, tx, k.ID)
		if err != nil {
			return err
		}
		ctx = db.WithTenant(ctx, tenant)
	}
	ctx = audit.WithActor(ctx, audit.Actor{Type: audit.ActorSystem})
	event := audit.Event{Action: "apikey.leaked", Entity: "api_key", EntityID: k.ID.String(), After: leakImage{URL: r.URL, Source: r.Source}}
	err := revoke(ctx, tx, k.ID, nil)
	switch {
	case errors.Is(err, ErrNotFound):
		event.Action = "apikey.leak_reported"
		return s.audit.Record(ctx, tx, event)
	case err != nil:
		return err
	}
	if err := s.audit.Record(ctx, tx, event); err != nil {
		return err
	}
	if s.onLeak != nil {
		return s.onLeak(ctx, tx, k, r)
	}
	return nil
}

func keyTenant(ctx context.Context, tx db.Transaction, id ID) (uuid.UUID, error) {
	rows, err := tx.Q().QueryContext(ctx, "SELECT tenant_id FROM api_keys WHERE id = $1", id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("apikeys: key tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenant uuid.UUID
	if !rows.Next() {
		return uuid.Nil, errors.Join(rows.Err(), ErrNotFound)
	}
	if err := rows.Scan(&tenant); err != nil {
		return uuid.Nil, err
	}
	return tenant, rows.Close()
}
