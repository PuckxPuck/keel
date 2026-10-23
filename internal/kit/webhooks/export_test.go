package webhooks

import (
	"context"
	"errors"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

// RecordAttempt records an outcome of generation gen as a delivery run would.
func (s *Service) RecordAttempt(ctx context.Context, tx db.Transaction, id DeliveryID, endpoint EndpointID, gen int, ok, final bool) error {
	a := attempt{ok: ok, status: 200}
	if !ok {
		a = attempt{status: 502, code: "http_status", err: errors.New("bad gateway")}
	}
	return s.recordAttempt(ctx, tx, id, endpoint, gen, a, final)
}
