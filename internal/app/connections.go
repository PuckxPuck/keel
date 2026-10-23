//go:build !noconnections

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/connections"
	"github.com/PuckxPuck/keel/internal/kit/oauthstate"
	"github.com/PuckxPuck/keel/internal/kit/seal"
)

// ConnectionConfig is APP_CONNECTION_*.
type ConnectionConfig = connections.Config

// connectionsWiring is the connections service, set with a database and keys.
type connectionsWiring struct {
	connections *connections.Service
}

// connectionProviders are the external accounts users may connect; keel has none. An app adds its
// providers here (and sets APP_CONNECTION_KEYS).
var connectionProviders = []connections.Provider{}

func connectionKeys(c Config) []config.Secret { return c.Connection.Keys } //nolint:unused // a hook webhooks.go calls; unused in an app without webhooks

func (w *wiring) openConnections(cfg Config, deps Deps) error {
	var err error
	w.connections, err = newConnections(cfg.Connection.Keys, oauthstate.Runner(appTx(deps.DB)))
	return err
}

// newConnections is the connections service on run, or nil without keys.
func newConnections(keys []config.Secret, run oauthstate.Runner) (*connections.Service, error) {
	if len(keys) == 0 {
		return nil, nil //nolint:nilnil // no keys means the part is off, which is not an error
	}
	ring, err := seal.NewKeyring(keys, "connections")
	if err != nil {
		return nil, fmt.Errorf("connection keys: %w", err)
	}
	return connections.New(connections.Options{Tx: run, Keys: ring, Providers: connectionProviders})
}

// connectionCommands run connection:rekey on the maintenance runner: under tenancy the operator pool, so
// one run reseals every tenant's tokens.
func connectionCommands(environ []string) []cli.Command {
	return connections.Commands(func(ctx context.Context) (*connections.Service, func(), error) {
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return nil, nil, err
		}
		svc, err := newConnections(cfg.Connection.Keys, oauthstate.Runner(maintenanceTx(deps)))
		if err == nil && svc == nil {
			err = errors.New("connections are off: set APP_CONNECTION_KEYS")
		}
		if err != nil {
			_ = deps.DB.Close()
			return nil, nil, err
		}
		return svc, func() { _ = deps.DB.Close() }, nil
	})
}

func connectionParts(cfg Config) []string {
	if len(cfg.Connection.Keys) > 0 {
		return []string{"connections"}
	}
	return nil
}

func connectionKeySets(cfg Config) []keySet {
	return []keySet{{name: "connection", keys: cfg.Connection.Keys}}
}
