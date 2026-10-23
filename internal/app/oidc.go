//go:build !nooidc

package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/oidc"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// OIDCConfig is APP_OIDC_*: the provider, and the realms that offer sign-in with it.
type OIDCConfig struct {
	oidc.Config
	Realms []string `env:"REALMS" envDefault:"tenant"`
}

func (c OIDCConfig) Validate(bool) error {
	var errs []error
	for _, name := range c.Realms {
		if !slices.ContainsFunc(realms(), func(r realm.Realm) bool { return r.Name == name }) {
			errs = append(errs, fmt.Errorf("APP_OIDC_REALMS names %q, which is not a realm with sign-in", name))
		}
	}
	return errors.Join(errs...)
}

// validateOIDC is OIDC's rule across settings: the callback needs the public URL.
func (c Config) validateOIDC() error {
	if c.OIDC.Enabled() && c.App.PublicURL == "" {
		return errors.New("OIDC sign-in needs APP_PUBLIC_URL for its callback")
	}
	return nil
}

// oidcWiring is the OIDC service, set with a database when an issuer is configured.
type oidcWiring struct {
	oidc *oidc.Service
}

func (w *wiring) openOIDC(cfg Config, run func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error) error {
	if !cfg.OIDC.Enabled() {
		return nil
	}
	var err error
	w.oidc, err = oidc.New(oidc.Options{
		Config: cfg.OIDC.Config, Realms: cfg.OIDC.Realms, RedirectURL: oidc.RedirectURL(cfg.App.PublicURL, BasePath+oidcCallbackPath),
		Tx: run, Audit: w.audit, Secure: cfg.Env.IsProd(),
	})
	return err
}

func oidcMapper(err error) (*problem.Problem, bool) { return oidc.Mapper(err) }

func oidcParts(cfg Config) []string {
	if cfg.OIDC.Enabled() {
		return []string{"oidc"}
	}
	return nil
}

const oidcCallbackPath = "/auth/oidc/callback"

type oidcStartInput struct {
	ReturnTo string `query:"returnTo" maxLength:"2048" doc:"A path on this site to land on after signing in"`
}

type oidcCallbackInput struct {
	State string `query:"state" maxLength:"128"`
	Code  string `query:"code" maxLength:"2048"`
}

// Redirect sends the browser on; it carries no body.
type Redirect struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

type boundStateKey struct{}

func (w *wiring) registerOIDC(api huma.API) {
	get := func(id, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, Summary: summary, Tags: tagAuth, DefaultStatus: http.StatusSeeOther}
	}
	httpx.Register(api, get("startOidcSignIn", "/auth/oidc/start", "Send the browser to the sign-in provider"), w.startOIDC, rbac.Public(), authClass)
	callback := get("finishOidcSignIn", oidcCallbackPath, "Finish signing in with the provider and return to the site")
	callback.Middlewares = huma.Middlewares{w.readBoundState}
	httpx.Register(api, callback, w.finishOIDC, rbac.Public(), authClass)
}

// readBoundState passes the binding cookie to the callback; its name depends on the production profile.
func (w *wiring) readBoundState(ctx huma.Context, next func(huma.Context)) {
	if w.oidc == nil {
		next(ctx)
		return
	}
	c, err := huma.ReadCookie(ctx, w.oidc.CookieName())
	if err != nil {
		next(ctx)
		return
	}
	next(huma.WithValue(ctx, boundStateKey{}, c.Value))
}

func (w *wiring) oidcReady(ctx context.Context) error {
	if err := w.ready(); err != nil {
		return err
	}
	if w.oidc == nil || !w.oidc.Enabled(httpx.Realm(ctx)) {
		return oidc.ErrNotEnabled
	}
	return nil
}

func (w *wiring) startOIDC(ctx context.Context, in *oidcStartInput) (*Redirect, error) {
	if err := w.oidcReady(ctx); err != nil {
		return nil, err
	}
	returnTo := ""
	if in.ReturnTo != "" {
		var ok bool
		if returnTo, ok = httpx.SafeReturnPath(in.ReturnTo); !ok {
			return nil, problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, "returnTo must be a path on this site")
		}
	}
	started, err := w.oidc.Start(ctx, returnTo)
	if err != nil {
		return nil, err
	}
	return &Redirect{Status: http.StatusSeeOther, Location: started.URL, SetCookie: []http.Cookie{*started.Cookie}}, nil
}

// finishOIDC links the verified person to their user and starts a browser session (the realm's MFA
// policy applies), then returns to the path given at the start.
func (w *wiring) finishOIDC(ctx context.Context, in *oidcCallbackInput) (*Redirect, error) {
	if err := w.oidcReady(ctx); err != nil {
		return nil, err
	}
	bound, _ := ctx.Value(boundStateKey{}).(string)
	claims, returnTo, err := w.oidc.Finish(ctx, in.State, bound, in.Code)
	if err != nil {
		return nil, err
	}
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		userID, err := w.oidc.Link(ctx, tx, claims)
		if err != nil {
			return err
		}
		_, err = w.sessions.Start(ctx, tx, userID, auth.Meta{Kind: auth.KindBrowser, Provider: "oidc"})
		return err
	})
	if errors.Is(err, auth.ErrNoAccess) {
		err = oidc.ErrRefused
	}
	if err != nil {
		return nil, err
	}
	if returnTo == "" {
		returnTo = "/"
	}
	return &Redirect{Status: http.StatusSeeOther, Location: returnTo, SetCookie: []http.Cookie{*w.oidc.ClearCookie()}}, nil
}
