// Package devices pairs shared devices (registers, kiosks) with a realm. A permission holder makes a
// short single-use pairing code; the device trades it for a "device_id.secret" bearer token whose hash
// is stored. Rotation keeps the previous secret valid for a grace window. The scope is an opaque
// string the app turns into grants.
package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-jet/jet/v2/mysql"
	"github.com/go-jet/jet/v2/postgres"
	"github.com/go-jet/jet/v2/qrm"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type deviceTag struct{}

type ID = ids.ID[deviceTag]

type Device struct {
	ID         ID         `json:"id" alias:"devices.id"`
	Realm      string     `json:"realm" alias:"devices.realm"`
	Name       string     `json:"name" alias:"devices.name"`
	Scope      string     `json:"scope" alias:"devices.scope"`
	CreatedBy  *users.ID  `json:"createdBy" alias:"devices.created_by"`
	CreatedAt  time.Time  `json:"createdAt" alias:"devices.created_at"`
	LastSeenAt *time.Time `json:"lastSeenAt" alias:"devices.last_seen_at"`
	RevokedAt  *time.Time `json:"revokedAt" alias:"devices.revoked_at"`
}

const (
	// CodeTTL is how long a pairing code works.
	CodeTTL = 10 * time.Minute
	// codeAlphabet is Crockford's base32: no I, L, O or U to misread.
	codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLen      = 8
	maxName      = 200
	maxScope     = 200
	touchEvery   = time.Minute
	maxToken     = 128
	// MaxGrace is the longest a rotated secret keeps working.
	MaxGrace = 24 * time.Hour
)

var (
	ErrInvalidCode  = errors.New("the pairing code is invalid or has expired")
	ErrNotFound     = errors.New("device not found")
	ErrInvalidToken = fmt.Errorf("device token is invalid: %w", auth.ErrInvalidToken)
	ErrInvalidInput = errors.New("device name must be 1 to 200 characters and scope at most 200")
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrInvalidCode):
		return problem.New(http.StatusUnprocessableEntity, "invalid_pairing_code", err.Error()), true
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, err.Error()), true
	case errors.Is(err, ErrInvalidInput):
		return problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, err.Error()), true
	}
	return nil, false
}

// Grants turns a device's scope into what it may do in its realm.
type Grants func(realm, scope string) []rbac.Grant

type Service struct {
	audit  *audit.Recorder
	grants Grants
}

func New(rec *audit.Recorder, grants Grants) *Service {
	if rec == nil || grants == nil {
		panic("devices: New needs a recorder and a grants function")
	}
	return &Service{audit: rec, grants: grants}
}

// NewPairingCode makes a code that pairs one device named name with scope in realm. The caller's
// operation decides who may; the code records who did.
func (s *Service) NewPairingCode(ctx context.Context, tx db.Transaction, actor users.Actor, realm, name, scope string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxName || utf8.RuneCountInString(scope) > maxScope || !utf8.ValidString(scope) {
		return "", ErrInvalidInput
	}
	code := newCode()
	now := now(ctx)
	var by *users.ID
	if id, ok := actor.ActingUser(); ok {
		by = &id
	}
	q := db.Rebind(tx.Dialect(), "INSERT INTO device_pairing_codes (code_hash, realm, name, scope, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.Q().ExecContext(ctx, q, codeHash(code), realm, name, scope, by, now, now.Add(CodeTTL)); err != nil {
		return "", fmt.Errorf("store pairing code: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "device.pairing_code_created", Entity: "device", After: map[string]string{"name": name, "scope": scope}}); err != nil {
		return "", err
	}
	return code[:4] + "-" + code[4:], nil
}

// Pair spends a pairing code made for realm and creates the device. The token is returned once.
func (s *Service) Pair(ctx context.Context, tx db.Transaction, realm, code string) (string, Device, error) {
	normalised, ok := normaliseCode(code)
	if !ok {
		return "", Device{}, ErrInvalidCode
	}
	hash := codeHash(normalised)
	q := db.Rebind(tx.Dialect(), "SELECT realm, name, scope, created_by, expires_at, used_at FROM device_pairing_codes WHERE code_hash = ? AND realm = ? FOR UPDATE")
	var d Device
	var createdBy uuid.NullUUID
	var expires time.Time
	var used sql.NullTime
	found, err := queryRow(ctx, tx, q, []any{hash, realm}, &d.Realm, &d.Name, &d.Scope, &createdBy, &expires, &used)
	if err != nil {
		return "", Device{}, fmt.Errorf("load pairing code: %w", err)
	}
	if !found {
		return "", Device{}, ErrInvalidCode
	}
	now := now(ctx)
	if used.Valid || !now.Before(expires) {
		return "", Device{}, ErrInvalidCode
	}
	spend := db.Rebind(tx.Dialect(), "UPDATE device_pairing_codes SET used_at = ? WHERE code_hash = ?")
	if _, err := tx.Q().ExecContext(ctx, spend, now, hash); err != nil {
		return "", Device{}, fmt.Errorf("spend pairing code: %w", err)
	}
	d.ID, d.CreatedAt = ids.NewOf[deviceTag](), now
	if createdBy.Valid {
		by := users.ID(createdBy.UUID)
		d.CreatedBy = &by
	}
	secret, secretHash := auth.NewSecret()
	ins := db.Rebind(tx.Dialect(), "INSERT INTO devices (id, realm, name, scope, secret_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.Q().ExecContext(ctx, ins, d.ID, d.Realm, d.Name, d.Scope, secretHash, d.CreatedBy, d.CreatedAt); err != nil {
		return "", Device{}, fmt.Errorf("create device: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "device.paired", Entity: "device", EntityID: d.ID.String(), After: d}); err != nil {
		return "", Device{}, err
	}
	return d.ID.String() + "." + secret, d, nil
}

// Rotate gives a device of realm a new secret; the old one keeps working until grace (clamped to 0 to
// MaxGrace) has passed.
func (s *Service) Rotate(ctx context.Context, tx db.Transaction, realm string, id ID, grace time.Duration) (string, error) {
	grace = min(max(grace, 0), MaxGrace)
	cur, err := secretsForUpdate(ctx, tx, id)
	if err != nil {
		return "", err
	}
	if cur.revoked || cur.realm != realm {
		return "", ErrNotFound
	}
	secret, hash := auth.NewSecret()
	q := db.Rebind(tx.Dialect(), "UPDATE devices SET secret_hash = ?, previous_secret_hash = ?, previous_valid_until = ? WHERE id = ?")
	if _, err := tx.Q().ExecContext(ctx, q, hash, cur.hash, now(ctx).Add(grace), id); err != nil {
		return "", fmt.Errorf("rotate device secret: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{Action: "device.rotated", Entity: "device", EntityID: id.String()}); err != nil {
		return "", err
	}
	return id.String() + "." + secret, nil
}

// Revoke stops the tokens of a device of realm at once.
func (s *Service) Revoke(ctx context.Context, tx db.Transaction, realm string, id ID) error {
	q := db.Rebind(tx.Dialect(), "UPDATE devices SET revoked_at = ? WHERE id = ? AND realm = ? AND revoked_at IS NULL")
	res, err := tx.Q().ExecContext(ctx, q, now(ctx), id, realm)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errors.Join(err, ErrNotFound)
	}
	return s.audit.Record(ctx, tx, audit.Event{Action: "device.revoked", Entity: "device", EntityID: id.String()})
}

// ResolveDevice checks a device token in realm and returns the device's principal; it makes Service an
// auth.DeviceResolver.
func (s *Service) ResolveDevice(ctx context.Context, tx db.Transaction, realm, raw string) (rbac.Principal, error) {
	id, hash, err := Parse(raw)
	if err != nil {
		return rbac.Principal{}, err
	}
	q := db.Rebind(tx.Dialect(), `SELECT realm, scope, secret_hash, previous_secret_hash, previous_valid_until, last_seen_at, revoked_at
		FROM devices WHERE id = ?`)
	var gotRealm, scope string
	var current, previous []byte
	var previousUntil, lastSeen, revoked sql.NullTime
	found, err := queryRow(ctx, tx, q, []any{id}, &gotRealm, &scope, &current, &previous, &previousUntil, &lastSeen, &revoked)
	if err != nil {
		return rbac.Principal{}, fmt.Errorf("load device: %w", err)
	}
	if !found {
		return rbac.Principal{}, ErrInvalidToken
	}
	now := now(ctx)
	matches := subtle.ConstantTimeCompare(hash, current) == 1
	inGrace := previousUntil.Valid && now.Before(previousUntil.Time) && subtle.ConstantTimeCompare(hash, previous) == 1
	if revoked.Valid || gotRealm != realm || (!matches && !inGrace) {
		return rbac.Principal{}, ErrInvalidToken
	}
	if !lastSeen.Valid || now.Sub(lastSeen.Time) >= touchEvery {
		touch := db.Rebind(tx.Dialect(), "UPDATE devices SET last_seen_at = ? WHERE id = ?")
		if _, err := tx.Q().ExecContext(ctx, touch, now, id); err != nil {
			return rbac.Principal{}, fmt.Errorf("touch device: %w", err)
		}
	}
	return rbac.NewSubject(rbac.SubjectDevice, id.UUID(), realm, s.grants(realm, scope)...), nil
}

var _ auth.DeviceResolver = (*Service)(nil)

var (
	colID, colRealm, colName, colScope    = postgres.StringColumn("id"), postgres.StringColumn("realm"), postgres.StringColumn("name"), postgres.StringColumn("scope")
	colCreatedBy                          = postgres.StringColumn("created_by")
	colCreatedAt, colLastSeen, colRevoked = postgres.TimestampzColumn("created_at"), postgres.TimestampzColumn("last_seen_at"), postgres.TimestampzColumn("revoked_at")
	deviceCols                            = []postgres.Column{colID, colRealm, colName, colScope, colCreatedBy, colCreatedAt, colLastSeen, colRevoked}
	pgDevices, myDevices                  = postgres.NewTable("", "devices", "", deviceCols...), mysql.NewTable("", "devices", "", deviceCols...)
)

// Sorts are the orders List supports: createdAt, oldest first, or -createdAt.
var Sorts = paging.Sorts[Device]{
	"createdAt": {
		{Column: colCreatedAt, Value: func(d Device) any { return d.CreatedAt }},
		{Column: colID, Value: func(d Device) any { return d.ID }},
	},
}

// List reads up to limit+1 devices of realm matching after (a paging.Keyset condition), for paging.Trim.
func List(ctx context.Context, tx db.Transaction, realm string, after postgres.BoolExpression, sort paging.Sort[Device], limit int) ([]Device, error) {
	// A raw bound value: postgres.String would add a cast MySQL cannot parse.
	where := colRealm.EQ(postgres.StringExp(postgres.Raw("#realm", postgres.RawArgs{"#realm": realm}))).AND(after)
	projection := make([]postgres.Projection, len(deviceCols))
	for i, c := range deviceCols {
		projection[i] = c
	}
	var out []Device
	var err error
	switch tx.Dialect() {
	case db.Postgres:
		err = postgres.SELECT(projection[0], projection[1:]...).FROM(pgDevices).WHERE(where).
			ORDER_BY(sort.OrderBy()...).LIMIT(int64(limit+1)).QueryContext(ctx, tx.Q(), &out)
	case db.MySQL:
		err = mysql.SELECT(projection[0], projection[1:]...).FROM(myDevices).WHERE(where).
			ORDER_BY(sort.OrderBy()...).LIMIT(int64(limit+1)).QueryContext(ctx, tx.Q(), &out)
	}
	if err != nil && !errors.Is(err, qrm.ErrNoRows) {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return out, nil
}

// ParseID reads a device id from a path parameter.
func ParseID(raw string) (ID, error) { return ids.Parse[deviceTag](raw) }

// Parse splits a "device_id.secret" token and hashes the secret.
func Parse(raw string) (ID, []byte, error) {
	if len(raw) > maxToken {
		return ID{}, nil, ErrInvalidToken
	}
	idPart, secret, ok := strings.Cut(raw, ".")
	if !ok {
		return ID{}, nil, ErrInvalidToken
	}
	id, err := ids.Parse[deviceTag](idPart)
	if err != nil || id.IsZero() || id.String() != idPart {
		return ID{}, nil, ErrInvalidToken
	}
	hash, err := auth.HashSecret(secret)
	if err != nil {
		return ID{}, nil, ErrInvalidToken
	}
	return id, hash, nil
}

type deviceSecrets struct {
	hash    []byte
	realm   string
	revoked bool
}

func secretsForUpdate(ctx context.Context, tx db.Transaction, id ID) (deviceSecrets, error) {
	q := db.Rebind(tx.Dialect(), "SELECT secret_hash, realm, revoked_at FROM devices WHERE id = ? FOR UPDATE")
	var out deviceSecrets
	var revoked sql.NullTime
	found, err := queryRow(ctx, tx, q, []any{id}, &out.hash, &out.realm, &revoked)
	if err != nil {
		return deviceSecrets{}, fmt.Errorf("load device: %w", err)
	}
	if !found {
		return deviceSecrets{}, ErrNotFound
	}
	out.revoked = revoked.Valid
	return out, nil
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

func newCode() string {
	b := make([]byte, codeLen)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

// normaliseCode accepts lower case, dashes and spaces, and the letters Crockford reads as digits.
func normaliseCode(code string) (string, bool) {
	if len(code) > 32 {
		return "", false
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(codeAlphabet, r) {
			return "", false
		}
		b.WriteRune(r)
	}
	return b.String(), b.Len() == codeLen
}

func codeHash(code string) []byte {
	sum := sha256.Sum256([]byte("pairing:" + code))
	return sum[:]
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}
