//go:build !noapikeys

package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/apikeys"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

const (
	// RealmAPI is the public API: bearer API keys on its own hosts, exposing operations marked
	// httpx.Public under APIBasePath.
	RealmAPI    = "api"
	APIBasePath = "/v1"
)

const PermAPIKeysManage rbac.Code = "api_keys.manage"

// apiKeyPerms join the tenant catalogue and the tenant realm's admin role.
var apiKeyPerms = []rbac.Perm{{
	Code: PermAPIKeysManage, Area: "Integrations", Label: "Manage API keys",
	Description: "Create and revoke API keys for plugins and integrations", Sensitive: true,
}}

// APIKeyConfig is APP_APIKEY_*.
type APIKeyConfig = apikeys.Config

// APIRealmConfig is the public api realm: bearer API keys on its own hosts. Without hosts the realm is
// not served.
type APIRealmConfig struct {
	Hosts []string `env:"HOSTS"`
}

// apikeysWiring is the keys service, set with or without a database.
type apikeysWiring struct {
	keys *apikeys.Service
}

// apiRealm serves the tenant realm's public operations to API keys. Its catalogue is the tenant's,
// since key scopes are tenant permissions.
func apiRealm(hosts []string) realm.Realm {
	return realm.Realm{Name: RealmAPI, Hosts: hosts, BasePath: APIBasePath, SpecPath: "/openapi", Catalogue: tenantCatalogue}
}

// apiPlaceholderHost stands in for APP_REALM_API_HOSTS where operations are listed without configuration.
const apiPlaceholderHost = "api.invalid"

// apiRealms is the api realm when it has hosts.
func apiRealms(cfg Config) []realm.Realm {
	if hosts := cfg.Realm.API.Hosts; len(hosts) > 0 {
		return []realm.Realm{apiRealm(hosts)}
	}
	return nil
}

// listedAPIRealms are the api realm on a placeholder host, for route listings.
func listedAPIRealms() []realm.Realm { return []realm.Realm{apiRealm([]string{apiPlaceholderHost})} }

func apiHosts(cfg Config) []string { return cfg.Realm.API.Hosts } //nolint:unused // a hook tenancy.go calls; unused in an app without tenancy

func (w *wiring) openAPIKeys(cfg Config) error {
	var err error
	w.keys, err = apikeys.New(apikeys.Options{
		Format: keyFormat(cfg), Realm: RealmAPI, Catalogue: tenantCatalogue, Manage: PermAPIKeysManage, Audit: w.audit, OnLeak: w.keyLeaked,
	})
	return err
}

// keyFormat is the key shape: the configured prefix, else the app's name when it fits the format, and
// live keys in production and staging, test keys elsewhere.
func keyFormat(cfg Config) apikeys.Format {
	prefix := cfg.APIKey.Prefix
	if prefix == "" {
		prefix = strings.ToLower(cfg.App.Name)
	}
	if !apikeys.ValidPrefix(prefix) {
		prefix = Name
	}
	env := apikeys.EnvTest
	if cfg.Env.IsProd() {
		env = apikeys.EnvLive
	}
	return apikeys.Format{Prefix: prefix, Env: env}
}

// tenantKeys is true under tenancy with a database: keys then belong to tenants.
func (w *wiring) tenantKeys() bool { return w.deps.Tenancy && w.db != nil }

// keyLocator and keyRunner find a presented key's tenant and open its transaction: under tenancy the
// global api_key_tenants table and the key's tenant's transaction, else one tenant and a plain one.
func (w *wiring) keyLocator() apikeys.Locator {
	if !w.tenantKeys() {
		return apikeys.NoTenancy{}
	}
	return apikeys.TenantLocator{DB: w.db}
}

func (w *wiring) keyRunner() apikeys.TxRunner {
	if !w.tenantKeys() {
		return w.keyTx
	}
	return apikeys.TenantTx(w.db)
}

// keyTx checks API keys in a plain transaction; without a database the api realm answers 503.
func (w *wiring) keyTx(ctx context.Context, _ apikeys.Tenant, fn func(ctx context.Context, tx db.Transaction) error) error {
	if w.db == nil {
		return errUnavailable
	}
	return db.InAppTx(ctx, w.db, fn)
}

// leakTx runs leak reports, which name keys of any tenant, on the operator pool under tenancy.
func (w *wiring) leakTx(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
	if !w.tenantKeys() {
		return db.InAppTx(ctx, w.db, fn)
	}
	return db.InOperatorTx(ctx, w.deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error { return fn(ctx, tx) })
}

// apiMiddleware is the api realm's chain (docs/architecture.md section 5).
func (w *wiring) apiMiddleware(api huma.API, limiter *ratelimit.Limiter, principals rbac.Principals, idem *idempotency.Store) huma.Middlewares {
	return huma.Middlewares{
		limiter.PreAuth(api, ratelimit.ClassPreAuth),
		w.keys.Middleware(api, w.keyLocator(), w.keyRunner()),
		w.guardTenant(RealmAPI, api, principals),
		limiter.Classes(api, keyClasses(limiter)),
		limiter.Middleware(api),
		rbac.Enforce(api, principals),
		apikeys.Lifecycle,
		idempotency.Middleware(api, idem, w.cfg.Idempotency, principals),
	}
}

// keyClasses limits a key's requests by key and by tenant; a key may name its own per-key class.
func keyClasses(limiter *ratelimit.Limiter) func(ctx context.Context) []string {
	return func(ctx context.Context) []string {
		k, ok := apikeys.FromContext(ctx)
		if !ok {
			return nil
		}
		perKey := ratelimit.ClassAPIKey
		if k.RateClass != "" && limiter.Defined(k.RateClass) {
			perKey = k.RateClass
		}
		return []string{perKey, ratelimit.ClassAPITenant}
	}
}

// registerAPIRealm documents the api realm and mirrors the tenant realm's public operations onto it.
func registerAPIRealm(set *realm.Set) {
	if public := set.API(RealmAPI); public != nil {
		apikeys.Document(public)
		httpx.Mirror(set.API(RealmTenant), public, httpx.IsPublic, apikeys.Expose)
	}
}

func checkAPIRealm(ctx context.Context, api huma.API) error {
	return apikeys.Check(api, clock.Wall(ctx).Now())
}

func apiKeysMapper(err error) (*problem.Problem, bool) { return apikeys.Mapper(err) }

func apiKeyParts(cfg Config) []string {
	if len(cfg.Realm.API.Hosts) > 0 {
		return []string{"apikeys"}
	}
	return nil
}

type listKeysInput struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"100" default:"50"`
	Cursor string `query:"cursor" maxLength:"64"`
}

type createKeyInput struct {
	Body struct {
		Name         string      `json:"name" minLength:"1" maxLength:"100"`
		Scopes       []rbac.Code `json:"scopes" maxItems:"100" doc:"Permission codes marked API-grantable that you hold yourself"`
		ExpiresAt    *time.Time  `json:"expiresAt,omitempty"`
		AllowedCIDRs []string    `json:"allowedCidrs,omitempty" maxItems:"20" doc:"Addresses the key works from, such as 203.0.113.0/24"`
	}
}

// CreatedKey is a new key and its plaintext, shown once.
type CreatedKey struct {
	Key    string      `json:"key" doc:"Shown once; store it now"`
	APIKey apikeys.Key `json:"apiKey"`
}

type keyIDInput struct {
	KeyID string `path:"keyId" format:"uuid"`
}

type leakReportInput struct {
	webhook.Headers
	RawBody []byte
}

type LeakResults struct {
	Results []apikeys.LeakResult `json:"results"`
}

var tagAPIKeys = []string{"api-keys"}

const leakSource = "apikey-leaks"

func (w *wiring) registerAPIKeys(api huma.API) {
	manage := rbac.Requires(PermAPIKeysManage)
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tagAPIKeys}
	}
	httpx.Register(api, op("listApiKeys", http.MethodGet, "/api-keys", "List API keys, newest first"), w.listKeys, manage, ratelimit.Class(ratelimit.ClassAPIRead))
	created := op("createApiKey", http.MethodPost, "/api-keys", "Create an API key; the key is shown once")
	created.DefaultStatus = http.StatusCreated
	httpx.Register(api, created, w.createKey, manage, ratelimit.Class(ratelimit.ClassAPIWrite))
	httpx.Register(api, op("revokeApiKey", http.MethodDelete, "/api-keys/{keyId}", "Stop an API key at once"), w.revokeKey,
		manage, ratelimit.Class(ratelimit.ClassAPIWrite))
	leaks := op("reportLeakedApiKeys", http.MethodPost, "/webhooks/api-key-leaks", "Revoke API keys a secret-scanning partner found in public")
	leaks.MaxBodyBytes = 256 << 10
	httpx.Register(api, leaks, w.reportLeaks, rbac.Public(), ratelimit.Class(ratelimit.ClassWebhook))
}

func (w *wiring) listKeys(ctx context.Context, in *listKeysInput) (*httpx.List[apikeys.Key], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	var before *apikeys.ID
	if in.Cursor != "" {
		id, err := apikeys.ParseID(in.Cursor)
		if err != nil {
			return nil, paging.ErrCursorInvalid
		}
		before = &id
	}
	var keys []apikeys.Key
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		keys, err = apikeys.List(ctx, tx, before, in.Limit+1)
		return err
	}, db.ReadOnly())
	if errors.Is(err, apikeys.ErrNotFound) {
		return nil, paging.ErrCursorInvalid
	}
	if err != nil {
		return nil, err
	}
	page := paging.Page[apikeys.Key]{Items: keys}
	if len(keys) > in.Limit {
		page.Items = keys[:in.Limit]
		page.Next = page.Items[in.Limit-1].ID.String()
	}
	self := &url.URL{Path: BasePath + "/api-keys", RawQuery: url.Values{"limit": {strconv.Itoa(in.Limit)}}.Encode()}
	return page.List(in.Limit, self), nil
}

func (w *wiring) createKey(ctx context.Context, in *createKeyInput) (*httpx.One[CreatedKey], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return nil, auth.ErrNoSession
	}
	var out CreatedKey
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out.Key, out.APIKey, err = w.keys.Create(ctx, tx, p, apikeys.NewKey{
			Name: in.Body.Name, Scopes: in.Body.Scopes, ExpiresAt: in.Body.ExpiresAt, AllowedCIDRs: in.Body.AllowedCIDRs,
		})
		return err
	})
	return one(out, err)
}

func (w *wiring) revokeKey(ctx context.Context, in *keyIDInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return nil, auth.ErrNoSession
	}
	id, err := apikeys.ParseID(in.KeyID)
	if err != nil {
		return nil, apikeys.ErrNotFound
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		return w.keys.Revoke(ctx, tx, p, id)
	}))
}

// reportLeaks takes a signed report of keys found in public, revokes the ones that are this app's and
// answers which were. A replayed delivery gets the same answer and changes nothing.
func (w *wiring) reportLeaks(ctx context.Context, in *leakReportInput) (*httpx.One[LeakResults], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	if len(w.cfg.APIKey.LeakSecrets) == 0 {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "no such route")
	}
	verifier, err := w.leakVerifier()
	if err != nil {
		return nil, err
	}
	if err := verifier.Verify(ctx, in.Headers, in.RawBody); err != nil {
		return nil, err
	}
	var reports []apikeys.Leak
	if err := json.Unmarshal(in.RawBody, &reports); err != nil || len(reports) > apikeys.MaxLeaks {
		return nil, problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, "the report must be a JSON array of at most 100 tokens")
	}
	out := LeakResults{Results: []apikeys.LeakResult{}}
	err = w.leakTx(ctx, func(ctx context.Context, tx db.Transaction) error {
		replayed, err := verifier.Seen(ctx, tx, in.ID)
		if err != nil {
			return err
		}
		results, err := w.keys.ReportLeaks(ctx, tx, reports, replayed)
		if results != nil {
			out.Results = results
		}
		return err
	})
	return one(out, err)
}

func (w *wiring) leakVerifier() (*webhook.Verifier, error) {
	secrets := make([]string, len(w.cfg.APIKey.LeakSecrets))
	for i, s := range w.cfg.APIKey.LeakSecrets {
		secrets[i] = s.Reveal()
	}
	return webhook.NewVerifier(webhook.Options{Source: leakSource, Secrets: secrets, Production: w.cfg.Env.IsProd()})
}

func apiKeyCommands(environ []string) []cli.Command {
	return []cli.Command{
		{Name: "apikey:list", Summary: "List API keys, revoked ones included", Flags: apiKeyListFlags, Run: apiKeyList(environ)},
		{Name: "apikey:create", Summary: "Create an API key as the system and print it once", Flags: apiKeyCreateFlags, Run: apiKeyCreate(environ)},
		{Name: "apikey:revoke", Summary: "Stop an API key at once", Flags: tenantFlag, Run: apiKeyRevoke(environ)},
	}
}

func apiKeyCreateFlags(fs *flag.FlagSet) {
	fs.String("name", "", "what the key is for")
	fs.String("scopes", "", "comma separated API-grantable permission codes")
	fs.Duration("expires-in", 0, "expire the key after this long (0: never)")
	fs.String("cidrs", "", "comma separated addresses the key works from")
	fs.String("rate-class", "", "a rate-limit class that replaces the per-key class for this key")
	tenantFlag(fs)
}

func apiKeyListFlags(fs *flag.FlagSet) {
	cli.JSONFlag(fs)
	tenantFlag(fs)
}

// apiKeyCreate issues a key as the system and prints it once.
func apiKeyCreate(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		in := apikeys.NewKey{Name: flagValue(fs, "name"), Scopes: codes(flagValue(fs, "scopes")), RateClass: flagValue(fs, "rate-class")}
		if cidrs := flagValue(fs, "cidrs"); cidrs != "" {
			in.AllowedCIDRs = strings.Split(cidrs, ",")
		}
		if in.Name == "" {
			return cli.Usagef("apikey:create needs --name")
		}
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		if in.RateClass != "" && !newLimiter(cfg.Rate, nil).Defined(in.RateClass) {
			return fmt.Errorf("rate class %q is not defined", in.RateClass)
		}
		if ttl, _ := fs.Lookup("expires-in").Value.(flag.Getter).Get().(time.Duration); ttl > 0 {
			at := clock.Wall(ctx).Now().Add(ttl)
			in.ExpiresAt = &at
		}
		plain, k, err := CreateAPIKey(ctx, cfg, deps, flagValue(fs, "tenant"), in)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(fs.Output(), "created %s (%s); the key is shown once:\n%s\n", k.ID, k.Name, plain)
		return err
	}
}

// CreateAPIKey issues a key as the system, which skips the check of what the creator holds but not
// which permissions a key may carry. Under tenancy the key is the named tenant's.
func CreateAPIKey(ctx context.Context, cfg Config, deps Deps, tenant string, in apikeys.NewKey) (string, apikeys.Key, error) {
	w, err := newWiring(cfg, deps)
	if err != nil {
		return "", apikeys.Key{}, err
	}
	if ctx, err = inTenant(ctx, deps, tenant); err != nil {
		return "", apikeys.Key{}, err
	}
	var plain string
	var k apikeys.Key
	err = db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
		var err error
		plain, k, err = w.keys.Create(ctx, tx, rbac.System(RealmTenant), in)
		return err
	})
	return plain, k, refusal(err)
}

func apiKeyList(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, _ []string) error {
		_, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		if ctx, err = inTenant(ctx, deps, flagValue(fs, "tenant")); err != nil {
			return err
		}
		table := cli.Table{Columns: []string{"id", "name", "hint", "scopes", "created_by", "created_at", "expires_at", "last_used_at", "revoked_at"}}
		var after *apikeys.ID
		for {
			var page []apikeys.Key
			if err := db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
				page, err = apikeys.List(ctx, tx, after, 500)
				return err
			}, db.ReadOnly()); err != nil {
				return err
			}
			for _, k := range page {
				scopes := make([]string, len(k.Scopes))
				for i, s := range k.Scopes {
					scopes[i] = string(s)
				}
				createdBy := ""
				if k.CreatedBy != nil {
					createdBy = k.CreatedBy.String()
				}
				table.Rows = append(table.Rows, []string{
					k.ID.String(), k.Name, k.Hint, strings.Join(scopes, ","), createdBy, stamp(&k.CreatedAt), stamp(k.ExpiresAt), stamp(k.LastUsedAt), stamp(k.RevokedAt),
				})
			}
			if len(page) < 500 {
				break
			}
			after = &page[len(page)-1].ID
		}
		return cli.Print(fs.Output(), cli.WantsJSON(fs), table)
	}
}

func apiKeyRevoke(environ []string) runFunc {
	return func(ctx context.Context, fs *flag.FlagSet, args []string) error {
		if len(args) != 1 {
			return cli.Usagef("apikey:revoke needs one key id")
		}
		id, err := apikeys.ParseID(args[0])
		if err != nil {
			return cli.Usagef("apikey:revoke needs a key id, such as one apikey:list shows")
		}
		cfg, deps, err := openForCommand(ctx, environ)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()
		w, err := newWiring(cfg, deps)
		if err != nil {
			return err
		}
		if ctx, err = inTenant(ctx, deps, flagValue(fs, "tenant")); err != nil {
			return err
		}
		if err := db.InAppTx(ctx, deps.DB, func(ctx context.Context, tx db.Transaction) error {
			return w.keys.Revoke(ctx, tx, rbac.System(RealmTenant), id)
		}); err != nil {
			return err
		}
		_, err = fmt.Fprintln(fs.Output(), "revoked "+id.String())
		return err
	}
}

func codes(list string) []rbac.Code {
	var out []rbac.Code
	for c := range strings.SplitSeq(list, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, rbac.Code(c))
		}
	}
	return out
}

// refusal spells out the broken rules for a terminal.
func refusal(err error) error {
	var refused *rbac.RefusedError
	if !errors.As(err, &refused) {
		return err
	}
	parts := make([]string, len(refused.Violations))
	for i, v := range refused.Violations {
		parts[i] = fmt.Sprintf("%s %v", v.Rule, v.Permissions)
	}
	return errors.New("refused: " + strings.Join(parts, "; "))
}

const (
	kindKeyReminders = "apikeys.expiry_reminders"
	kindKeyReminder  = "apikeys.expiry_reminder"
	kindKeyLeaked    = "apikeys.leak_notice"
)

// keyReminderWindows are when key owners hear that a key expires: two weeks before, then a day before.
var keyReminderWindows = []time.Duration{14 * 24 * time.Hour, 24 * time.Hour}

// apiKeyMaintenance schedules the daily expiry reminders, a global kind on maintenanceTx.
func (w *wiring) apiKeyMaintenance() {
	w.queue.Handle(kindKeyReminders, func(ctx context.Context, job jobs.Job) error { return w.fanOutKeyReminders(ctx, job) }, jobs.Global())
	w.queue.Schedule(kindKeyReminders, kindKeyReminders, "0 8 * * *", time.UTC)
}

// fanOutKeyReminders queues one reminder job per tenant (one without tenancy), so each reads and mails
// in its own tenant's transaction.
func (w *wiring) fanOutKeyReminders(ctx context.Context, job jobs.Job) error {
	return eachTenant(ctx, w.deps, false, func(ctx context.Context) error {
		return maintenanceTx(w.deps)(ctx, func(ctx context.Context, tx db.Transaction) error {
			_, err := w.queue.Enqueue(ctx, tx, kindKeyReminder, nil, jobs.Unique(kindKeyReminder+":"+job.ID.String()))
			return err
		})
	})
}

type leakPayload struct {
	Key  apikeys.ID `json:"key"`
	Name string     `json:"name"`
	Hint string     `json:"hint"`
	URL  string     `json:"url,omitempty"`
}

// apiKeyNotices adds the kinds that mail people about their keys; they run in the key's tenant.
func (w *wiring) apiKeyNotices() {
	w.queue.Handle(kindKeyReminder, func(ctx context.Context, _ jobs.Job) error { return w.remindKeys(ctx) })
	w.queue.Handle(kindKeyLeaked, jobs.Typed(func(ctx context.Context, _ jobs.Job, p leakPayload) error {
		return db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
			_, err := w.notifyAdmins(ctx, tx, AdminNotice{Perm: PermAPIKeysManage, Kind: "apikey_leaked", Fields: map[string]string{
				"Key": p.Name, "Hint": p.Hint, "Where": p.URL,
			}})
			return err
		})
	}))
}

// remindKeys mails the key managers of the context's tenant about keys that expire soon, once per window.
func (w *wiring) remindKeys(ctx context.Context) error {
	return db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		for _, within := range keyReminderWindows {
			due, err := apikeys.DueForReminder(ctx, tx, within)
			if err != nil {
				return err
			}
			for _, k := range due {
				queued, err := w.notifyAdmins(ctx, tx, AdminNotice{Perm: PermAPIKeysManage, Kind: "apikey_expiring", Fields: map[string]string{
					"Key": k.Name, "Hint": k.Hint, "Expires": k.ExpiresAt.UTC().Format(time.DateOnly),
				}})
				if err != nil {
					return err
				}
				if queued == 0 {
					continue
				}
				if err := apikeys.MarkReminded(ctx, tx, k.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// keyLeaked runs in the transaction that revoked a reported key. That is an operator transaction under
// tenancy, so the mail goes through a job that reads the key's tenant's managers in its own transaction.
func (w *wiring) keyLeaked(ctx context.Context, tx db.Transaction, k apikeys.Key, r apikeys.Leak) error {
	if w.queue == nil {
		return nil
	}
	_, err := w.queue.Enqueue(ctx, tx, kindKeyLeaked, leakPayload{Key: k.ID, Name: k.Name, Hint: k.Hint, URL: r.URL})
	return err
}
