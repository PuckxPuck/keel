//go:build nomail

package app

import (
	"context"

	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/config"
)

type (
	MailConfig struct{}
	Mailer     = struct{}
	mailWiring struct{}
)

// openMail leaves the notifier to the app outside local: Build refuses to serve without one.
func (w *wiring) openMail(cfg Config, _ Deps) error {
	if w.notifier == nil && cfg.Env == config.EnvLocal {
		w.notifier = tokens.LogNotifier{}
	}
	return nil
}

func mailParts(Config) []string { return nil }

func mailChecks(context.Context, Config) []Check { return nil }
