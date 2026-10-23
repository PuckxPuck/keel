// Package passkey registers WebAuthn passkeys and signs people in with them through go-webauthn.
// Challenges are kept server-side in auth_challenges, single use and short lived; passwordless sign-in
// requires user verification, so a passkey sign-in counts as both factors. A passkey works only on the
// realm it was registered on. A sign count that goes backwards (a cloned authenticator) is logged and
// refused.
package passkey

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// Config is APP_PASSKEY_*: the relying party id (a registrable domain, such as example.app) and the
// exact origins ceremonies may run on.
type Config struct {
	RPID    string   `env:"RP_ID"`
	Origins []string `env:"ORIGINS"`
}

func (c Config) Enabled() bool { return c.RPID != "" }

func (c Config) Validate(prod bool) error {
	if !c.Enabled() {
		if len(c.Origins) > 0 {
			return errors.New("passkey origins need PASSKEY_RP_ID")
		}
		return nil
	}
	var errs []error
	if strings.ContainsAny(c.RPID, ":/ ") || c.RPID != strings.ToLower(c.RPID) {
		errs = append(errs, fmt.Errorf("passkey relying party id %q must be a lower case host name", c.RPID))
	}
	if len(c.Origins) == 0 {
		errs = append(errs, errors.New("passkey origins are required with a relying party id"))
	}
	for _, o := range c.Origins {
		if err := validOrigin(o, c.RPID, prod); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validOrigin(origin, rpID string, prod bool) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("passkey origin %q must be an exact origin such as https://app.example.com", origin)
	}
	host := u.Hostname()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && !prod && host == "localhost":
	default:
		return fmt.Errorf("passkey origin %q must be https (http only for localhost outside production)", origin)
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("passkey origin %q is not on the relying party id %s", origin, rpID)
	}
	return nil
}

const (
	// ChallengeTTL is how long a ceremony may take.
	ChallengeTTL      = 5 * time.Minute
	purposeRegister   = "passkey_register"
	purposeSignIn     = "passkey_sign_in"
	maxName           = 100
	maxResponse       = 64 << 10
	CodeInvalid       = "passkey_invalid"
	CodeChallenge     = "passkey_challenge_invalid"
	CodeAlreadyExists = "passkey_exists"
	CodeLastFactor    = "passkey_last_factor"
)

var (
	ErrChallenge = errors.New("passkey: the ceremony is invalid or has expired; start again")
	ErrInvalid   = errors.New("passkey: the passkey could not be verified")
	ErrExists    = errors.New("passkey: this passkey is already registered")
	ErrName      = errors.New("passkey: name must be 1 to 100 characters")
	ErrNotFound  = errors.New("passkey: not found")
	// ErrLastFactor refuses removing the last second factor of a realm that requires one.
	ErrLastFactor = errors.New("passkey: this realm requires a second factor and this passkey is your last; add another first")
	errNoRealm    = errors.New("passkey: the request has no realm")
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrChallenge):
		return problem.New(http.StatusBadRequest, CodeChallenge, ErrChallenge.Error()), true
	case errors.Is(err, ErrInvalid):
		return problem.New(http.StatusUnauthorized, CodeInvalid, ErrInvalid.Error()), true
	case errors.Is(err, ErrExists):
		return problem.New(http.StatusConflict, CodeAlreadyExists, ErrExists.Error()), true
	case errors.Is(err, ErrName):
		return problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, ErrName.Error()), true
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, ErrNotFound.Error()), true
	case errors.Is(err, ErrLastFactor):
		return problem.New(http.StatusConflict, CodeLastFactor, ErrLastFactor.Error()), true
	}
	return nil, false
}

// TxRunner opens the transactions ceremonies work in: plain, or tenant transactions under tenancy.
type TxRunner func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error

type Options struct {
	Config Config
	// DisplayName is the relying party's name shown by authenticators.
	DisplayName string
	Tx          TxRunner
	Audit       *audit.Recorder
}

type Service struct {
	wa    *webauthn.WebAuthn
	tx    TxRunner
	audit *audit.Recorder
}

func New(o Options) (*Service, error) {
	if o.Tx == nil || o.Audit == nil || !o.Config.Enabled() {
		return nil, errors.New("passkey: a relying party id, a transaction runner and an audit recorder are required")
	}
	required := protocol.ResidentKeyRequirementRequired
	wa, err := webauthn.New(&webauthn.Config{
		RPID: o.Config.RPID, RPDisplayName: o.DisplayName, RPOrigins: o.Config.Origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: required, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{wa: wa, tx: o.Tx, audit: o.Audit}, nil
}

type passkeyTag struct{}

type ID = ids.ID[passkeyTag]

// ParseID reads a passkey id from a path parameter.
func ParseID(raw string) (ID, error) { return ids.Parse[passkeyTag](raw) }

// Passkey is a registered credential as the app shows it.
type Passkey struct {
	ID         ID         `json:"id"`
	Name       string     `json:"name"`
	Version    int        `json:"version"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

// Challenge is what the browser passes to navigator.credentials: Options, and the id to send back.
type Challenge struct {
	ID      uuid.UUID       `json:"challengeId"`
	Options json.RawMessage `json:"options"`
}

type account struct {
	id    users.ID
	email string
	name  string
	creds []webauthn.Credential
}

func (a account) WebAuthnID() []byte                         { return a.id[:] }
func (a account) WebAuthnName() string                       { return a.email }
func (a account) WebAuthnDisplayName() string                { return a.name }
func (a account) WebAuthnCredentials() []webauthn.Credential { return a.creds }

// BeginRegistration starts adding a passkey for u; passkeys u already has are excluded.
func (s *Service) BeginRegistration(ctx context.Context, tx db.Transaction, u users.User) (Challenge, error) {
	creds, err := credentialsOf(ctx, tx, u.ID)
	if err != nil {
		return Challenge{}, err
	}
	acct := account{id: u.ID, email: u.Email, name: u.Name, creds: creds}
	if acct.name == "" {
		acct.name = u.Email
	}
	creation, session, err := s.wa.BeginRegistration(acct, webauthn.WithExclusions(webauthn.Credentials(creds).CredentialDescriptors()))
	if err != nil {
		return Challenge{}, fmt.Errorf("passkey: begin registration: %w", err)
	}
	return s.store(ctx, tx, purposeRegister, &u.ID, session, creation)
}

// FinishRegistration spends the challenge (whatever happens next), verifies the authenticator's answer
// for userID and stores the passkey, then runs then in the same transaction.
func (s *Service) FinishRegistration(ctx context.Context, userID users.ID, challengeID uuid.UUID, response []byte, name string,
	then func(ctx context.Context, tx db.Transaction, p Passkey) error,
) (Passkey, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxName {
		return Passkey{}, ErrName
	}
	session, err := s.take(ctx, challengeID, purposeRegister, &userID)
	if err != nil {
		return Passkey{}, err
	}
	parsed, err := parse(response, protocol.ParseCredentialCreationResponseBytes)
	if err != nil {
		return Passkey{}, err
	}
	var out Passkey
	err = s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.Get(ctx, tx, userID)
		if err != nil {
			return err
		}
		cred, err := s.wa.CreateCredential(account{id: u.ID, email: u.Email, name: u.Name}, session, parsed)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if out, err = s.insert(ctx, tx, userID, cred, name); err != nil {
			return err
		}
		return then(ctx, tx, out)
	})
	return out, err
}

func (s *Service) insert(ctx context.Context, tx db.Transaction, userID users.ID, cred *webauthn.Credential, name string) (Passkey, error) {
	realm := httpx.Realm(ctx)
	if realm == "" {
		return Passkey{}, errNoRealm
	}
	if _, found, err := byCredentialID(ctx, tx, cred.ID, false); err != nil || found {
		return Passkey{}, errors.Join(err, ErrExists)
	}
	p := Passkey{ID: ids.NewOf[passkeyTag](), Name: name, Version: 1, CreatedAt: now(ctx)}
	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}
	var aaguid []byte
	if len(cred.Authenticator.AAGUID) == 16 {
		aaguid = cred.Authenticator.AAGUID
	}
	q := db.Rebind(tx.Dialect(), `INSERT INTO passkeys (id, user_id, realm, credential_id, public_key, sign_count, transports, aaguid, flags,
		attestation_type, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.Q().ExecContext(ctx, q, p.ID, userID, realm, cred.ID, cred.PublicKey, int64(cred.Authenticator.SignCount),
		truncate(strings.Join(transports, " "), 200), aaguid, int(cred.Flags.MsgpByte()), truncate(cred.AttestationType, 64), name, p.CreatedAt,
		p.CreatedAt); err != nil {
		return Passkey{}, fmt.Errorf("passkey: store: %w", err)
	}
	uid := userID.UUID()
	actx := audit.WithActor(ctx, audit.Actor{Type: audit.ActorUser, ID: &uid})
	if err := s.audit.Record(actx, tx, audit.Event{Action: "passkey.registered", Entity: "passkey", EntityID: p.ID.String(), After: p}); err != nil {
		return Passkey{}, err
	}
	return p, nil
}

// BeginSignIn starts a passwordless sign-in with a discoverable passkey; user verification is required.
func (s *Service) BeginSignIn(ctx context.Context, tx db.Transaction) (Challenge, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Challenge{}, fmt.Errorf("passkey: begin sign-in: %w", err)
	}
	return s.store(ctx, tx, purposeSignIn, nil, session, assertion)
}

// FinishSignIn spends the challenge (whatever happens next), verifies the assertion, records the new
// sign count and runs then (start the session) in the same transaction as that write. A passkey of
// another realm, and a sign count that did not move forward (logged), are refused.
func (s *Service) FinishSignIn(ctx context.Context, challengeID uuid.UUID, response []byte, then func(ctx context.Context, tx db.Transaction, userID users.ID) error) error {
	session, err := s.take(ctx, challengeID, purposeSignIn, nil)
	if err != nil {
		return err
	}
	parsed, err := parse(response, protocol.ParseCredentialRequestResponseBytes)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		stored, found, err := byCredentialID(ctx, tx, parsed.RawID, true)
		if err != nil {
			return err
		}
		if !found || stored.realm != httpx.Realm(ctx) || !bytes.Equal(parsed.Response.UserHandle, stored.userID[:]) {
			return ErrInvalid
		}
		u, err := users.Get(ctx, tx, stored.userID)
		if err != nil || u.Status != users.Active {
			return errors.Join(err, ErrInvalid)
		}
		acct := account{id: u.ID, email: u.Email, name: u.Name, creds: []webauthn.Credential{stored.cred}}
		_, cred, err := s.wa.ValidatePasskeyLogin(func([]byte, []byte) (webauthn.User, error) { return acct, nil }, session, parsed)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if cred.Authenticator.CloneWarning {
			logx.From(ctx).Warn("passkey sign count did not increase; refusing a possibly cloned authenticator",
				"passkey_id", stored.id.String(), "stored", stored.cred.Authenticator.SignCount, "presented", parsed.Response.AuthenticatorData.Counter)
			return ErrInvalid
		}
		q := db.Rebind(tx.Dialect(), "UPDATE passkeys SET sign_count = ?, flags = ?, last_used_at = ? WHERE id = ?")
		if _, err := tx.Q().ExecContext(ctx, q, int64(cred.Authenticator.SignCount), int(cred.Flags.MsgpByte()), now(ctx), stored.id); err != nil {
			return fmt.Errorf("passkey: record use: %w", err)
		}
		return then(ctx, tx, u.ID)
	})
}

// List returns up to limit of the user's passkeys on the request's realm, oldest first.
func List(ctx context.Context, tx db.Transaction, userID users.ID, limit int) ([]Passkey, error) {
	q := db.Rebind(tx.Dialect(), "SELECT "+shownColumns+" FROM passkeys WHERE user_id = ? AND realm = ? ORDER BY created_at, id LIMIT ?")
	rows, err := tx.Q().QueryContext(ctx, q, userID, httpx.Realm(ctx), limit)
	if err != nil {
		return nil, fmt.Errorf("passkey: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Passkey{}
	for rows.Next() {
		p, err := scanShown(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Rename renames one of the user's passkeys on the request's realm at the version the caller read; a
// stale version is an occ.StaleError.
func (s *Service) Rename(ctx context.Context, tx db.Transaction, userID users.ID, id ID, version int, name string) (Passkey, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxName {
		return Passkey{}, ErrName
	}
	before, err := own(ctx, tx, userID, id)
	if err != nil {
		return Passkey{}, err
	}
	at := now(ctx)
	q := db.Rebind(tx.Dialect(), "UPDATE passkeys SET name = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?")
	res, err := tx.Q().ExecContext(ctx, q, name, at, id, version)
	if err != nil {
		return Passkey{}, fmt.Errorf("passkey: rename: %w", err)
	}
	if err := occ.Check(ctx, res, current(tx, userID, id)); err != nil {
		return Passkey{}, err
	}
	after, err := own(ctx, tx, userID, id)
	if err != nil {
		return Passkey{}, err
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "passkey.renamed", Entity: "passkey", EntityID: id.String(), Before: before, After: after}); err != nil {
		return Passkey{}, err
	}
	return after, nil
}

// Remove deletes one of the user's passkeys on the request's realm. allow, when set, sees how many
// passkeys the user keeps there and may refuse (ErrLastFactor); the user's passkeys on the realm stay
// locked until tx ends, so two removals cannot each count the other as kept.
func (s *Service) Remove(ctx context.Context, tx db.Transaction, userID users.ID, id ID, allow func(ctx context.Context, tx db.Transaction, kept int) error) error {
	q := db.Rebind(tx.Dialect(), "SELECT id FROM passkeys WHERE user_id = ? AND realm = ? FOR UPDATE")
	rows, err := tx.Q().QueryContext(ctx, q, userID, httpx.Realm(ctx))
	if err != nil {
		return fmt.Errorf("passkey: lock: %w", err)
	}
	defer func() { _ = rows.Close() }()
	found, kept := false, 0
	for rows.Next() {
		var got ID
		if err := rows.Scan(&got); err != nil {
			return err
		}
		if got == id {
			found = true
			continue
		}
		kept++
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if allow != nil {
		if err := allow(ctx, tx, kept); err != nil {
			return err
		}
	}
	before, err := own(ctx, tx, userID, id)
	if err != nil {
		return err
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM passkeys WHERE id = ?"), id); err != nil {
		return fmt.Errorf("passkey: remove: %w", err)
	}
	return s.audit.Record(ctx, tx, audit.Event{Action: "passkey.removed", Entity: "passkey", EntityID: id.String(), Before: before})
}

const shownColumns = "id, name, version, created_at, last_used_at"

func scanShown(rows *sql.Rows) (Passkey, error) {
	var p Passkey
	if err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return Passkey{}, fmt.Errorf("passkey: scan: %w", err)
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, nil
}

// own reads one of the user's passkeys on the request's realm; any other is ErrNotFound.
func own(ctx context.Context, tx db.Transaction, userID users.ID, id ID) (Passkey, error) {
	q := db.Rebind(tx.Dialect(), "SELECT "+shownColumns+" FROM passkeys WHERE id = ? AND user_id = ? AND realm = ?")
	rows, err := tx.Q().QueryContext(ctx, q, id, userID, httpx.Realm(ctx))
	if err != nil {
		return Passkey{}, fmt.Errorf("passkey: load: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Passkey{}, err
		}
		return Passkey{}, ErrNotFound
	}
	p, err := scanShown(rows)
	if err != nil {
		return Passkey{}, err
	}
	return p, rows.Close()
}

func current(tx db.Transaction, userID users.ID, id ID) func(ctx context.Context) (occ.Current, error) {
	return func(ctx context.Context) (occ.Current, error) {
		var cur occ.Current
		q := db.Rebind(tx.Dialect(), "SELECT version, updated_at FROM passkeys WHERE id = ? AND user_id = ? AND realm = ?")
		found, err := queryRow(ctx, tx, q, []any{id, userID, httpx.Realm(ctx)}, &cur.Version, &cur.ChangedAt)
		switch {
		case err != nil:
			return occ.Current{}, err
		case !found:
			return occ.Current{}, ErrNotFound
		}
		by := userID.UUID()
		cur.ChangedBy = &by
		return cur, nil
	}
}

// Prune deletes challenges that expired before before.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM auth_challenges WHERE expires_at < ?"), before)
	if err != nil {
		return 0, fmt.Errorf("passkey: prune: %w", err)
	}
	return res.RowsAffected()
}

func parse[T any](response []byte, fn func([]byte) (*T, error)) (*T, error) {
	if len(response) == 0 || len(response) > maxResponse {
		return nil, ErrInvalid
	}
	parsed, err := fn(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return parsed, nil
}

func (s *Service) store(ctx context.Context, tx db.Transaction, purpose string, userID *users.ID, session *webauthn.SessionData, options any) (Challenge, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return Challenge{}, err
	}
	opts, err := json.Marshal(options)
	if err != nil {
		return Challenge{}, err
	}
	c := Challenge{ID: ids.New(), Options: opts}
	t := now(ctx)
	q := db.Rebind(tx.Dialect(), "INSERT INTO auth_challenges (id, purpose, user_id, data, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
	if _, err := tx.Q().ExecContext(ctx, q, c.ID, purpose, userID, string(data), t.Add(ChallengeTTL), t); err != nil {
		return Challenge{}, fmt.Errorf("passkey: store challenge: %w", err)
	}
	return c, nil
}

// take spends a challenge in its own transaction, so a failed ceremony cannot be retried with it.
func (s *Service) take(ctx context.Context, id uuid.UUID, purpose string, userID *users.ID) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	var refused error
	err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		q := db.Rebind(tx.Dialect(), "SELECT purpose, user_id, data, expires_at FROM auth_challenges WHERE id = ? FOR UPDATE")
		var gotPurpose, data string
		var gotUser *users.ID
		var expires time.Time
		found, err := queryRow(ctx, tx, q, []any{id}, &gotPurpose, &gotUser, &data, &expires)
		if err != nil || !found {
			refused = ErrChallenge
			return err
		}
		if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM auth_challenges WHERE id = ?"), id); err != nil {
			return fmt.Errorf("passkey: spend challenge: %w", err)
		}
		sameUser := (userID == nil && gotUser == nil) || (userID != nil && gotUser != nil && *userID == *gotUser)
		if gotPurpose != purpose || !sameUser || !now(ctx).Before(expires) || json.Unmarshal([]byte(data), &session) != nil {
			refused = ErrChallenge
		}
		return nil
	})
	if err = errors.Join(err, refused); err != nil {
		return webauthn.SessionData{}, err
	}
	return session, nil
}

type storedCredential struct {
	id     ID
	userID users.ID
	realm  string
	cred   webauthn.Credential
}

const passkeyColumns = "id, user_id, realm, credential_id, public_key, sign_count, transports, aaguid, flags, attestation_type" //nolint:gosec // column names, not a credential

func scanCredential(rows *sql.Rows) (storedCredential, error) {
	var c storedCredential
	var count int64
	var flags int
	var transports string
	var aaguid []byte
	if err := rows.Scan(&c.id, &c.userID, &c.realm, &c.cred.ID, &c.cred.PublicKey, &count, &transports, &aaguid, &flags, &c.cred.AttestationType); err != nil {
		return storedCredential{}, err
	}
	c.cred.Authenticator.SignCount = uint32(min(max(count, 0), 1<<32-1)) //nolint:gosec // clamped to the uint32 range
	c.cred.Authenticator.AAGUID = aaguid
	c.cred.Flags = webauthn.CredentialFlagsFromMsgpByte(byte(flags & 0xff))
	for t := range strings.FieldsSeq(transports) {
		c.cred.Transport = append(c.cred.Transport, protocol.AuthenticatorTransport(t))
	}
	return c, nil
}

func byCredentialID(ctx context.Context, tx db.Transaction, credentialID []byte, lock bool) (storedCredential, bool, error) {
	q := "SELECT " + passkeyColumns + " FROM passkeys WHERE credential_id = ?"
	if lock {
		q += " FOR UPDATE"
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), credentialID)
	if err != nil {
		return storedCredential{}, false, fmt.Errorf("passkey: load: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return storedCredential{}, false, rows.Err()
	}
	c, err := scanCredential(rows)
	if err != nil {
		return storedCredential{}, false, err
	}
	return c, true, rows.Close()
}

func credentialsOf(ctx context.Context, tx db.Transaction, userID users.ID) ([]webauthn.Credential, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT "+passkeyColumns+" FROM passkeys WHERE user_id = ?"), userID)
	if err != nil {
		return nil, fmt.Errorf("passkey: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []webauthn.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c.cred)
	}
	return out, rows.Err()
}

func queryRow(ctx context.Context, tx db.Transaction, q string, args []any, dest ...any) (bool, error) {
	rows, err := tx.Q().QueryContext(ctx, q, args...)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return false, rows.Err()
	}
	if err := rows.Scan(dest...); err != nil {
		return false, err
	}
	return true, rows.Close()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}
