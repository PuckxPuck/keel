//go:build !nowebhooks

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/seal"
	"github.com/PuckxPuck/keel/internal/kit/webhooks"
)

// WebhooksOutConfig is APP_WEBHOOKS_OUT_*.
type WebhooksOutConfig = webhooks.Config

// webhooksWiring is the outbound webhooks service, set with a database and keys.
type webhooksWiring struct {
	webhooks *webhooks.Service
}

// webhookKeys are the keys that seal endpoint secrets: APP_WEBHOOKS_OUT_KEYS, else the connection keys.
// Without either the outbound webhooks part is off.
func webhookKeys(c Config) []config.Secret {
	if len(c.WebhooksOut.Keys) > 0 {
		return c.WebhooksOut.Keys
	}
	return connectionKeys(c)
}

func (w *wiring) openWebhooks(cfg Config, deps Deps) error {
	keys := webhookKeys(cfg)
	if len(keys) == 0 {
		return nil
	}
	ring, err := seal.NewKeyring(keys, "webhooks")
	if err != nil {
		return fmt.Errorf("webhooks out keys: %w", err)
	}
	w.webhooks, err = webhooks.New(webhooks.Options{
		Queue: w.queue, Tx: jobTx(deps), Keys: ring, Config: cfg.WebhooksOut, Audit: w.audit, OnDisabled: w.webhookDisabled,
	})
	return err
}

// webhookDisabled runs in the delivery's transaction, the endpoint's tenant's under tenancy.
func (w *wiring) webhookDisabled(ctx context.Context, tx db.Transaction, ep webhooks.Endpoint) error {
	_, err := w.notifyAdmins(ctx, tx, AdminNotice{Perm: PermAccessManage, Kind: "webhook_disabled", Fields: map[string]string{"URL": ep.URL}})
	return err
}

func webhookCommands(environ []string) []cli.Command {
	return webhooks.Commands(func(ctx context.Context) (*webhooks.Service, func(), error) {
		w, done, err := openAssembled(ctx, environ)
		if err != nil {
			return nil, nil, err
		}
		if w.webhooks == nil {
			done()
			return nil, nil, errors.New("outbound webhooks are off: set APP_WEBHOOKS_OUT_KEYS or APP_CONNECTION_KEYS")
		}
		return w.webhooks, done, nil
	})
}

func webhookParts(cfg Config) []string {
	if len(webhookKeys(cfg)) > 0 {
		return []string{"webhooks"}
	}
	return nil
}

func webhookKeySets(cfg Config) []keySet {
	return []keySet{{name: "webhooks out", keys: cfg.WebhooksOut.Keys}}
}
