//go:build !nopasskey

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/passkey"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// PasskeyConfig is APP_PASSKEY_*.
type PasskeyConfig = passkey.Config

// passkeyWiring is the passkey service, set with a database when a relying party is configured.
type passkeyWiring struct {
	passkeys *passkey.Service
}

func (w *wiring) openPasskeys(cfg Config, run func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error) error {
	if !cfg.Passkey.Enabled() {
		return nil
	}
	var err error
	w.passkeys, err = passkey.New(passkey.Options{Config: cfg.Passkey, DisplayName: issuer(cfg), Tx: passkey.TxRunner(run), Audit: w.audit})
	return err
}

// authPrunes clear expired passkey challenges with the rest of sign-in state.
func authPrunes() []func(context.Context, db.Transaction, time.Time) (int64, error) {
	return []func(context.Context, db.Transaction, time.Time) (int64, error){passkey.Prune}
}

func passkeyMapper(err error) (*problem.Problem, bool) { return passkey.Mapper(err) }

func passkeyParts(cfg Config) []string {
	if cfg.Passkey.Enabled() {
		return []string{"passkeys"}
	}
	return nil
}

type passkeyRegisterInput struct {
	Body struct {
		ChallengeID uuid.UUID       `json:"challengeId" format:"uuid"`
		Name        string          `json:"name" minLength:"1" maxLength:"100"`
		Credential  json.RawMessage `json:"credential" doc:"The PublicKeyCredential from navigator.credentials.create, as JSON"`
	}
}

type passkeyIDInput struct {
	PasskeyID string `path:"passkeyId" format:"uuid"`
}

// Huma does not fill path parameters declared in an embedded struct, so the id is a field of its own.
type passkeyRenameInput struct {
	PasskeyID string `path:"passkeyId" format:"uuid"`
	Body      struct {
		Name    string `json:"name" minLength:"1" maxLength:"100"`
		Version int    `json:"version" minimum:"1" doc:"The version you read; a stale one is 409"`
	}
}

type passkeySignInInput struct {
	Body struct {
		ChallengeID uuid.UUID       `json:"challengeId" format:"uuid"`
		Credential  json.RawMessage `json:"credential" doc:"The PublicKeyCredential from navigator.credentials.get, as JSON"`
		Session     SessionType     `json:"session,omitempty" enum:"cookie,bearer" default:"cookie"`
	}
}

func (w *wiring) registerPasskeys(api huma.API) {
	post := func(id, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodPost, Path: path, Summary: summary, Tags: tagAuth}
	}
	write := ratelimit.Class(ratelimit.ClassAPIWrite)
	httpx.Register(api, post("beginPasskeyRegistration", "/auth/passkeys/register/begin", "Start adding a passkey to the signed-in user"),
		w.beginPasskeyRegistration, rbac.SignedIn(), write)
	httpx.Register(api, post("finishPasskeyRegistration", "/auth/passkeys/register/finish", "Finish adding a passkey; other sessions end"),
		w.finishPasskeyRegistration, rbac.SignedIn(), authClass)
	httpx.Register(api, post("beginPasskeySignIn", "/auth/passkeys/sign-in/begin", "Start signing in with a passkey"),
		w.beginPasskeySignIn, rbac.Public(), authClass)
	httpx.Register(api, post("finishPasskeySignIn", "/auth/passkeys/sign-in/finish", "Sign in with a passkey; it counts as both factors"),
		w.finishPasskeySignIn, rbac.Public(), authClass)
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tagAuth}
	}
	httpx.Register(api, op("listPasskeys", http.MethodGet, "/auth/passkeys", "List the signed-in user's passkeys on this site"),
		w.listPasskeys, rbac.SignedIn(), ratelimit.Class(ratelimit.ClassAPIRead))
	httpx.Register(api, op("renamePasskey", http.MethodPatch, "/auth/passkeys/{passkeyId}", "Rename one of your passkeys"),
		w.renamePasskey, rbac.SignedIn(), write)
	httpx.Register(api, op("removePasskey", http.MethodDelete, "/auth/passkeys/{passkeyId}", "Remove one of your passkeys; other sessions end"),
		w.removePasskey, rbac.SignedIn(), write)
}

func (w *wiring) passkeysReady() error {
	if err := w.ready(); err != nil {
		return err
	}
	if w.passkeys == nil {
		return problem.New(http.StatusNotFound, problem.CodeNotFound, "passkeys are not enabled")
	}
	return nil
}

func (w *wiring) beginPasskeyRegistration(ctx context.Context, _ *struct{}) (*httpx.One[passkey.Challenge], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	var out passkey.Challenge
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.Get(ctx, tx, s.UserID)
		if err != nil {
			return err
		}
		out, err = w.passkeys.BeginRegistration(ctx, tx, u)
		return err
	})
	return one(out, err)
}

// finishPasskeyRegistration stores the passkey and, like confirming any new authenticator, ends the
// user's other sessions.
func (w *wiring) finishPasskeyRegistration(ctx context.Context, in *passkeyRegisterInput) (*httpx.One[passkey.Passkey], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	return one(w.passkeys.FinishRegistration(ctx, s.UserID, in.Body.ChallengeID, in.Body.Credential, in.Body.Name,
		func(ctx context.Context, tx db.Transaction, _ passkey.Passkey) error {
			return w.sessions.RevokeOthers(ctx, tx, s.UserID, s.ID)
		}))
}

func (w *wiring) beginPasskeySignIn(ctx context.Context, _ *struct{}) (*httpx.One[passkey.Challenge], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	var out passkey.Challenge
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out, err = w.passkeys.BeginSignIn(ctx, tx)
		return err
	})
	return one(out, err)
}

func (w *wiring) finishPasskeySignIn(ctx context.Context, in *passkeySignInInput) (*httpx.One[SignedIn], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	kind := auth.KindBrowser
	if in.Body.Session == SessionBearer {
		kind = auth.KindAPI
	}
	var out SignedIn
	err := w.passkeys.FinishSignIn(ctx, in.Body.ChallengeID, in.Body.Credential, func(ctx context.Context, tx db.Transaction, userID users.ID) error {
		started, err := w.sessions.Start(ctx, tx, userID, auth.Meta{Kind: kind, Provider: "passkey", SecondFactorPassed: true})
		out = signedIn(started)
		return err
	})
	if errors.Is(err, auth.ErrNoAccess) {
		err = passkey.ErrInvalid
	}
	return one(out, err)
}

// maxListedPasskeys bounds the list, which has no further pages: nobody keeps that many.
const maxListedPasskeys = 100

func (w *wiring) listPasskeys(ctx context.Context, _ *struct{}) (*httpx.List[passkey.Passkey], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	var out []passkey.Passkey
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out, err = passkey.List(ctx, tx, s.UserID, maxListedPasskeys)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	return httpx.ListOf(out, httpx.ListMeta{Limit: maxListedPasskeys}, httpx.Links{}), nil
}

func (w *wiring) renamePasskey(ctx context.Context, in *passkeyRenameInput) (*httpx.One[passkey.Passkey], error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	id, err := passkey.ParseID(in.PasskeyID)
	if err != nil {
		return nil, passkey.ErrNotFound
	}
	var out passkey.Passkey
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out, err = w.passkeys.Rename(ctx, tx, s.UserID, id, in.Body.Version, in.Body.Name)
		return err
	})
	return one(out, err)
}

// removePasskey ends the user's other sessions too, since one of them may have used the passkey. It
// refuses to take the last second factor of a realm that requires one.
func (w *wiring) removePasskey(ctx context.Context, in *passkeyIDInput) (*httpx.NoContent, error) {
	if err := w.passkeysReady(); err != nil {
		return nil, err
	}
	s, err := personSession(ctx)
	if err != nil {
		return nil, err
	}
	id, err := passkey.ParseID(in.PasskeyID)
	if err != nil {
		return nil, passkey.ErrNotFound
	}
	required := w.realmMFA(httpx.Realm(ctx)) == realm.MFARequired
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		err := w.passkeys.Remove(ctx, tx, s.UserID, id, func(ctx context.Context, tx db.Transaction, kept int) error {
			if !required || kept > 0 {
				return nil
			}
			if w.totp != nil {
				if enrolled, err := w.totp.Enrolled(ctx, tx, s.UserID); err != nil || enrolled {
					return err
				}
			}
			return passkey.ErrLastFactor
		})
		if err != nil {
			return err
		}
		return w.sessions.RevokeOthers(ctx, tx, s.UserID, s.ID)
	}))
}

// realmMFA is the MFA policy of the named realm.
func (w *wiring) realmMFA(name string) realm.MFA {
	for _, r := range configuredRealms(w.cfg) {
		if r.Name == name {
			return r.MFA
		}
	}
	return realm.MFAOff
}
