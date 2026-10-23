package app

import (
	"context"
	"errors"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/devices"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/auth/totp"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// wiring holds the services auth operations use. Without a database (route:list, tests without one)
// the services are nil and those operations answer 503.
type wiring struct {
	cfg       Config
	db        *db.DB
	audit     *audit.Recorder
	sessions  *auth.Sessions
	passwords *password.Service
	totp      *totp.Service
	devices   *devices.Service
	cursors   *paging.Keyset
	failures  *auth.Failures
	// notifier is nil outside local when the app configured none; Build refuses to serve then.
	notifier tokens.Notifier
	// admins is nil without the mail part when the app passed none; production then refuses to serve
	// with API keys or outbound webhooks on.
	admins AdminNotifier
	access *rbac.Access
	oidcWiring
	passkeyWiring
	apikeysWiring
	tenancyWiring
	deps Deps
	// queue and the parts on it are set with a database; webhooks, connections and pdf only when
	// configured; files by Build when APP_FILES_DRIVER names storage.
	queue *jobs.Queue
	mailWiring
	webhooksWiring
	connectionsWiring
	pdfWiring
	filesWiring
	// modules are the instances mounted: their operations, mappers and jobs all come from these.
	modules []Module
}

var (
	mfaPerAccount = ratelimit.Rate{Limit: 5, Period: 15 * time.Minute}
	mfaPerUser    = ratelimit.Rate{Limit: 20, Period: 15 * time.Minute}
	// mfaStreak is the run of wrong codes, cleared by a right one, that revokes every session.
	mfaStreak       = ratelimit.Rate{Limit: 10, Period: 24 * time.Hour}
	resetRequests   = ratelimit.Rate{Limit: 5, Period: time.Hour}
	resetPerAddress = ratelimit.Rate{Limit: 20, Period: time.Hour}
	verifyRequests  = ratelimit.Rate{Limit: 5, Period: time.Hour}
	pairPerAddress  = ratelimit.Rate{Limit: 10, Period: 15 * time.Minute}
)

var errNoAdminNotifier = errors.New("no admin notifier is configured: in production, API keys and outbound webhooks need one to report leaked keys and disabled endpoints (the mail part, or Deps.AdminNotifier)")

// AdminNotice is a security notice for the active users holding Perm on the tenant realm (the context's
// tenant's under tenancy). Kind names it (apikey_leaked, apikey_expiring, webhook_disabled); Fields are
// its details by name.
type AdminNotice struct {
	Perm   rbac.Code
	Kind   string
	Fields map[string]string
}

// AdminNotifier queues an AdminNotice for delivery in tx, the event's transaction, and returns how many
// deliveries it queued.
type AdminNotifier interface {
	NotifyAdmins(ctx context.Context, tx db.Transaction, n AdminNotice) (queued int, err error)
}

// notifyAdmins hands n to the admin notifier and returns how many deliveries were queued; without a
// notifier (outside production) the notice is dropped with a warning and none were.
//
//nolint:unused // called by the mail, apikeys and webhooks parts; an app without all three never calls it
func (w *wiring) notifyAdmins(ctx context.Context, tx db.Transaction, n AdminNotice) (int, error) {
	if w.admins == nil {
		logx.From(ctx).Warn("a security notice was not delivered: no admin notifier", "kind", n.Kind)
		return 0, nil
	}
	return w.admins.NotifyAdmins(ctx, tx, n)
}

var errNoNotifier = errors.New("no notifier is configured: outside APP_ENV=local, reset, verification and invite links need one (the mail part, or Deps.Notifier)")

func newWiring(cfg Config, deps Deps) (*wiring, error) {
	w := &wiring{
		cfg: cfg, db: deps.DB, deps: deps, audit: audit.New(audit.Options{Chain: cfg.Audit.Chain}), notifier: deps.Notifier, admins: deps.AdminNotifier,
	}
	if len(cfg.MFA.Keys) > 0 {
		var err error
		if w.totp, err = totp.New(cfg.MFA.Keys, issuer(cfg), w.audit); err != nil {
			return nil, err
		}
	}
	w.devices = devices.New(w.audit, deviceGrants)
	if err := w.setupTenancy(cfg, deps); err != nil {
		return nil, err
	}
	sessions, err := newSessions(cfg, deps.DB, w.audit, w.totp, w.devices, w.sessionTenancy())
	if err != nil {
		return nil, err
	}
	w.sessions = sessions
	w.access = NewAccess(w.audit, rbac.WithHook(sessions))
	if err := w.openAPIKeys(cfg); err != nil {
		return nil, err
	}
	if deps.DB == nil {
		if w.notifier == nil && cfg.Env == config.EnvLocal {
			w.notifier = tokens.LogNotifier{}
		}
		w.modules = mounted(w)
		return w, nil
	}
	if err := w.openServices(cfg, deps); err != nil {
		return nil, err
	}
	run := appTx(deps.DB)
	if err := w.openOIDC(cfg, run); err != nil {
		return nil, err
	}
	if err := w.openPasskeys(cfg, run); err != nil {
		return nil, err
	}
	if w.cursors, err = paging.NewKeyset(deps.DB.Dialect(), cfg.SigningKeys()...); err != nil {
		return nil, err
	}
	w.failures = auth.NewFailures(ratelimit.DBStoreOf(deps.DB))
	if cfg.Password.Enabled {
		hasher, err := password.NewHasher(cfg.Password.Argon2, cfg.Password.MaxConcurrent)
		if err != nil {
			return nil, err
		}
		w.passwords = password.NewService(hasher, w.failures, password.DefaultThrottle, w.audit)
	}
	return w, nil
}

// mountModules builds the modules once the wiring is complete (files included) and puts their jobs on
// the queue; assemble calls it after opening files.
func (w *wiring) mountModules() {
	w.modules = mounted(w)
	for _, m := range w.modules {
		m.Jobs(w.queue)
	}
}

// appTx opens the request's transaction for kit services that run their own: the tenant's when the
// request has one, plain otherwise.
func appTx(d *db.DB) func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
	return func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
		return db.InAppTx(ctx, d, fn)
	}
}

// deviceGrants turns a device's scope into its grants. keel has no device permissions; an app maps its
// scopes (a till, a kiosk) to the permissions those devices need.
func deviceGrants(string, string) []rbac.Grant { return nil }

func newSessions(cfg Config, d *db.DB, rec *audit.Recorder, second *totp.Service, dev *devices.Service, tenants auth.Tenancy) (*auth.Sessions, error) {
	opts := auth.Options{DB: d, Audit: rec, Realms: configuredRealms(cfg), Secure: cfg.Env.IsProd(), Devices: dev, Tenancy: tenants}
	if second != nil {
		opts.SecondFactor = second
	}
	return auth.NewSessions(opts)
}

func issuer(cfg Config) string {
	if cfg.App.Name != "" {
		return cfg.App.Name
	}
	return Name
}

// statusGuard is users' guard: the access rules, then revoking a disabled user's sessions.
type statusGuard struct {
	access   *rbac.Access
	sessions *auth.Sessions
}

func (g statusGuard) CheckStatus(ctx context.Context, tx db.Transaction, actor users.Actor, target users.ID, to users.Status) error {
	if err := g.access.CheckStatus(ctx, tx, actor, target, to); err != nil {
		return err
	}
	if to == users.Disabled {
		return g.sessions.RevokeUser(ctx, tx, target)
	}
	return nil
}

func (w *wiring) users() *users.Service {
	return users.NewService(w.audit, statusGuard{access: w.access, sessions: w.sessions})
}
