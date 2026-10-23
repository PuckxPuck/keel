package db

import (
	"context"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/health"
)

// HealthCheck pings the app pool and, when configured, the operator pool.
func HealthCheck(d *DB) health.Check {
	return health.Check{Name: "database", Run: func(ctx context.Context) error {
		if err := d.app.PingContext(ctx); err != nil {
			return fmt.Errorf("app pool: %w", err)
		}
		if d.operator != nil {
			if err := d.operator.PingContext(ctx); err != nil {
				return fmt.Errorf("operator pool: %w", err)
			}
		}
		return nil
	}}
}
