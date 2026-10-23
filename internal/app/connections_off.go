//go:build noconnections

package app

import (
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/config"
)

type (
	ConnectionConfig  struct{}
	connectionsWiring struct{}
)

func connectionKeys(Config) []config.Secret { return nil }

func (w *wiring) openConnections(Config, Deps) error { return nil }

func connectionCommands([]string) []cli.Command { return nil }

func connectionParts(Config) []string { return nil }

func connectionKeySets(Config) []keySet { return nil }
