//go:build nowebhooks

package app

import "github.com/PuckxPuck/keel/internal/kit/cli"

type (
	WebhooksOutConfig struct{}
	webhooksWiring    struct{}
)

func (w *wiring) openWebhooks(Config, Deps) error { return nil }

func webhookCommands([]string) []cli.Command { return nil }

func webhookParts(Config) []string { return nil }

func webhookKeySets(Config) []keySet { return nil }
