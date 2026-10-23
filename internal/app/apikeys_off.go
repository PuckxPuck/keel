//go:build noapikeys

package app

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// RealmAPI names the public api realm, which comes with the apikeys part and is not served without it.
const RealmAPI = "api"

var apiKeyPerms []rbac.Perm

type (
	APIKeyConfig   struct{}
	APIRealmConfig struct{}
	apikeysWiring  struct{}
)

func apiRealms(Config) []realm.Realm { return nil }

func listedAPIRealms() []realm.Realm { return nil }

func apiHosts(Config) []string { return nil }

func (w *wiring) openAPIKeys(Config) error { return nil }

func (w *wiring) apiMiddleware(huma.API, *ratelimit.Limiter, rbac.Principals, *idempotency.Store) huma.Middlewares {
	return nil
}

func registerAPIRealm(*realm.Set) {}

func checkAPIRealm(context.Context, huma.API) error { return nil }

func apiKeysMapper(error) (*problem.Problem, bool) { return nil, false }

func apiKeyParts(Config) []string { return nil }

func (w *wiring) registerAPIKeys(huma.API) {}

func apiKeyCommands([]string) []cli.Command { return nil }

func (w *wiring) apiKeyMaintenance() {}

func (w *wiring) apiKeyNotices() {}
