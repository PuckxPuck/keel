// Package totp is the TOTP second factor (RFC 6238, 30-second steps, one step of skew): secrets
// encrypted at rest, enrolment confirmed by a code, the last used step stored so a code cannot be
// replayed, and ten single-use recovery codes stored hashed.
package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const (
	period        = 30
	skew          = 1
	secretSize    = 20
	recoveryCount = 10
	recoveryBytes = 10
	saltSize      = 16
	maxCodeInput  = 64
)

// Config is APP_MFA_*.
type Config struct {
	Keys []config.Secret `env:"KEYS"`
}

func (c Config) Validate(prod bool) error {
	var errs []error
	for i, k := range c.Keys {
		errs = append(errs, config.RequireStrong(fmt.Sprintf("MFA key %d", i+1), k, prod))
	}
	return errors.Join(errs...)
}

var (
	ErrInvalidCode     = errors.New("the code is not right")
	ErrNotEnrolled     = errors.New("no authenticator is set up")
	ErrAlreadyEnrolled = errors.New("an authenticator is already set up")
)

const (
	CodeInvalidCode     = "invalid_code"
	CodeNotEnrolled     = "mfa_not_enrolled"
	CodeAlreadyEnrolled = "mfa_already_enrolled"
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrInvalidCode):
		return problem.New(http.StatusUnprocessableEntity, CodeInvalidCode, err.Error()), true
	case errors.Is(err, ErrNotEnrolled):
		return problem.New(http.StatusConflict, CodeNotEnrolled, err.Error()), true
	case errors.Is(err, ErrAlreadyEnrolled):
		return problem.New(http.StatusConflict, CodeAlreadyEnrolled, err.Error()), true
	}
	return nil, false
}

type Service struct {
	keys   keyring
	issuer string
	audit  *audit.Recorder
}

// New takes the MFA keys newest first and the issuer shown in authenticator apps.
func New(keys []config.Secret, issuer string, rec *audit.Recorder) (*Service, error) {
	ring, err := newKeyring(keys)
	if err != nil {
		return nil, err
	}
	if rec == nil || issuer == "" {
		return nil, errors.New("totp: New needs an issuer and a recorder")
	}
	return &Service{keys: ring, issuer: issuer, audit: rec}, nil
}

// Enrolment is shown to the user once: the secret for manual entry and the otpauth URI for a QR code.
type Enrolment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// Enrol starts (or restarts) an unconfirmed enrolment. A confirmed one is never replaced here.
func (s *Service) Enrol(ctx context.Context, tx db.Transaction, u users.User) (Enrolment, error) {
	row, found, err := load(ctx, tx, u.ID)
	if err != nil {
		return Enrolment{}, err
	}
	if found && row.confirmedAt != nil {
		return Enrolment{}, ErrAlreadyEnrolled
	}
	key, err := otptotp.Generate(otptotp.GenerateOpts{
		Issuer: s.issuer, AccountName: u.Email, Period: period, SecretSize: secretSize,
		Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return Enrolment{}, fmt.Errorf("generate totp secret: %w", err)
	}
	now := now(ctx)
	sealed := s.keys.seal([]byte(key.Secret()), aad(u.ID))
	res, err := tx.Q().ExecContext(ctx, enrolSQL[tx.Dialect()], u.ID, sealed, now, now)
	if err != nil {
		return Enrolment{}, fmt.Errorf("store totp secret: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return Enrolment{}, errors.Join(err, ErrAlreadyEnrolled)
	}
	if err := s.record(ctx, tx, u.ID, "mfa.totp_enrolment_started"); err != nil {
		return Enrolment{}, err
	}
	return Enrolment{Secret: key.Secret(), URI: key.URL()}, nil
}

// enrolSQL starts or restarts an enrolment in one statement, so two first enrolments at once do not
// collide on the key, and never touches a confirmed one.
var enrolSQL = map[db.Dialect]string{
	db.Postgres: `INSERT INTO mfa_totp (user_id, secret_enc, created_at, updated_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET secret_enc = excluded.secret_enc, created_at = excluded.created_at,
		updated_at = excluded.updated_at, last_step = NULL WHERE mfa_totp.confirmed_at IS NULL`,
	db.MySQL: `INSERT INTO mfa_totp (user_id, secret_enc, created_at, updated_at) VALUES (?, ?, ?, ?) AS new
		ON DUPLICATE KEY UPDATE secret_enc = IF(mfa_totp.confirmed_at IS NULL, new.secret_enc, mfa_totp.secret_enc),
		last_step = IF(mfa_totp.confirmed_at IS NULL, NULL, mfa_totp.last_step),
		created_at = IF(mfa_totp.confirmed_at IS NULL, new.created_at, mfa_totp.created_at),
		updated_at = IF(mfa_totp.confirmed_at IS NULL, new.updated_at, mfa_totp.updated_at)`,
}

// Confirm activates a pending enrolment with a code from the app and returns ten recovery codes, shown once.
func (s *Service) Confirm(ctx context.Context, tx db.Transaction, userID users.ID, code string) ([]string, error) {
	row, found, err := loadForUpdate(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotEnrolled
	}
	if row.confirmedAt != nil {
		return nil, ErrAlreadyEnrolled
	}
	if err := s.check(ctx, tx, userID, row, code); err != nil {
		return nil, err
	}
	q := db.Rebind(tx.Dialect(), "UPDATE mfa_totp SET confirmed_at = ? WHERE user_id = ?")
	if _, err := tx.Q().ExecContext(ctx, q, now(ctx), userID); err != nil {
		return nil, fmt.Errorf("confirm totp: %w", err)
	}
	if err := s.record(ctx, tx, userID, "mfa.totp_confirmed"); err != nil {
		return nil, err
	}
	return s.RecoveryCodes(ctx, tx, userID)
}

// Verify checks a code against the confirmed secret. Each time step is accepted once.
func (s *Service) Verify(ctx context.Context, tx db.Transaction, userID users.ID, code string) error {
	row, found, err := loadForUpdate(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !found || row.confirmedAt == nil {
		return ErrNotEnrolled
	}
	return s.check(ctx, tx, userID, row, code)
}

// Enrolled is true when the user has a confirmed authenticator; it makes Service an auth.SecondFactor.
func (s *Service) Enrolled(ctx context.Context, tx db.Transaction, userID users.ID) (bool, error) {
	row, found, err := load(ctx, tx, userID)
	return found && row.confirmedAt != nil, err
}

// check accepts a code for the current step or one either side, newer than the last step used, then
// stores its step. A secret opened with an older key is sealed again with the newest.
func (s *Service) check(ctx context.Context, tx db.Transaction, userID users.ID, row secretRow, code string) error {
	code = strings.TrimSpace(code)
	if len(code) != int(otp.DigitsSix) {
		return ErrInvalidCode
	}
	secret, stale, err := s.keys.open(row.secretEnc, aad(userID))
	if err != nil {
		return err
	}
	current := clock.Wall(ctx).Now().Unix() / period
	matched := int64(-1)
	for step := current - skew; step <= current+skew; step++ {
		if step < 0 || (row.lastStep != nil && step <= *row.lastStep) {
			continue
		}
		want, err := otptotp.GenerateCodeCustom(string(secret), time.Unix(step*period, 0), otptotp.ValidateOpts{
			Period: period, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return fmt.Errorf("totp code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched = step
		}
	}
	if matched < 0 {
		return ErrInvalidCode
	}
	args := []any{matched, now(ctx)}
	q := "UPDATE mfa_totp SET last_step = ?, updated_at = ?"
	if stale {
		q += ", secret_enc = ?"
		args = append(args, s.keys.seal(secret, aad(userID)))
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q+" WHERE user_id = ?"), append(args, userID)...); err != nil {
		return fmt.Errorf("store totp step: %w", err)
	}
	return nil
}

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// RecoveryCodes replaces the user's recovery codes with ten new ones and returns them, shown once.
func (s *Service) RecoveryCodes(ctx context.Context, tx db.Transaction, userID users.ID) ([]string, error) {
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM mfa_recovery_codes WHERE user_id = ?"), userID); err != nil {
		return nil, fmt.Errorf("replace recovery codes: %w", err)
	}
	now := now(ctx)
	q := db.Rebind(tx.Dialect(), "INSERT INTO mfa_recovery_codes (id, user_id, salt, code_hash, created_at) VALUES (?, ?, ?, ?, ?)")
	codes := make([]string, recoveryCount)
	for i := range codes {
		raw := make([]byte, recoveryBytes)
		salt := make([]byte, saltSize)
		_, _ = rand.Read(raw) // crypto/rand.Read never fails
		_, _ = rand.Read(salt)
		plain := strings.ToLower(recoveryEncoding.EncodeToString(raw))
		codes[i] = plain[:4] + "-" + plain[4:8] + "-" + plain[8:12] + "-" + plain[12:]
		if _, err := tx.Q().ExecContext(ctx, q, ids.New(), userID, salt, recoveryHash(salt, plain), now); err != nil {
			return nil, fmt.Errorf("store recovery code: %w", err)
		}
	}
	if err := s.record(ctx, tx, userID, "mfa.recovery_codes_issued"); err != nil {
		return nil, err
	}
	return codes, nil
}

// UseRecovery spends one recovery code in place of a TOTP code.
func (s *Service) UseRecovery(ctx context.Context, tx db.Transaction, userID users.ID, code string) error {
	if len(code) > maxCodeInput {
		return ErrInvalidCode
	}
	plain := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	q := db.Rebind(tx.Dialect(), "SELECT id, salt, code_hash FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL FOR UPDATE")
	rows, err := tx.Q().QueryContext(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("load recovery codes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var hit *uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var salt, hash []byte
		if err := rows.Scan(&id, &salt, &hash); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(recoveryHash(salt, plain), hash) == 1 {
			hit = &id
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if hit == nil {
		return ErrInvalidCode
	}
	spend := db.Rebind(tx.Dialect(), "UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL")
	res, err := tx.Q().ExecContext(ctx, spend, now(ctx), *hit)
	if err != nil {
		return fmt.Errorf("spend recovery code: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, ErrInvalidCode)
	}
	return s.record(ctx, tx, userID, "mfa.recovery_code_used")
}

func recoveryHash(salt []byte, plain string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(plain))
	return h.Sum(nil)
}

func (s *Service) record(ctx context.Context, tx db.Transaction, userID users.ID, action string) error {
	return s.audit.Record(ctx, tx, audit.Event{Action: action, Entity: "user", EntityID: userID.String()})
}

type secretRow struct {
	secretEnc   []byte
	confirmedAt *time.Time
	lastStep    *int64
}

func load(ctx context.Context, tx db.Transaction, userID users.ID) (secretRow, bool, error) {
	return loadWith(ctx, tx, "SELECT secret_enc, confirmed_at, last_step FROM mfa_totp WHERE user_id = ?", userID)
}

// loadForUpdate locks the row, so two codes checked at once cannot both use the same step.
func loadForUpdate(ctx context.Context, tx db.Transaction, userID users.ID) (secretRow, bool, error) {
	return loadWith(ctx, tx, "SELECT secret_enc, confirmed_at, last_step FROM mfa_totp WHERE user_id = ? FOR UPDATE", userID)
}

func loadWith(ctx context.Context, tx db.Transaction, q string, userID users.ID) (secretRow, bool, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), userID)
	if err != nil {
		return secretRow{}, false, fmt.Errorf("load totp: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return secretRow{}, false, rows.Err()
	}
	var r secretRow
	var confirmed sql.NullTime
	var step sql.NullInt64
	if err := rows.Scan(&r.secretEnc, &confirmed, &step); err != nil {
		return secretRow{}, false, err
	}
	if confirmed.Valid {
		t := confirmed.Time.UTC()
		r.confirmedAt = &t
	}
	if step.Valid {
		r.lastStep = &step.Int64
	}
	return r, true, rows.Err()
}

func aad(userID users.ID) []byte { return []byte("totp:" + userID.String()) }

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}
