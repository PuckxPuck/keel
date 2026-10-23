package devices_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/devices"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const sell rbac.Code = "sales.create"

var at = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

func grants(_, scope string) []rbac.Grant {
	if scope == "till" {
		return []rbac.Grant{{Perm: sell}}
	}
	return nil
}

func TestDevices_PairRotateRevoke(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		svc := devices.New(audit.New(audit.Options{}), grants)
		inTx := func(when time.Time, fn func(ctx context.Context, tx db.Tx[db.Plain]) error) error {
			return db.InTx(clock.WithWall(t.Context(), clock.Fixed(when)), e.DB(), fn)
		}
		resolve := func(when time.Time, realm, token string) (rbac.Principal, error) {
			var p rbac.Principal
			err := inTx(when, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				p, err = svc.ResolveDevice(ctx, tx, realm, token)
				return err
			})
			return p, err
		}
		var code string
		require.NoError(t, inTx(at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			code, err = svc.NewPairingCode(ctx, tx, rbac.System("tenant"), "tenant", "Front till", "till")
			return err
		}))
		pair := func(when time.Time, code string) (string, devices.Device, error) {
			var token string
			var d devices.Device
			err := inTx(when, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				token, d, err = svc.Pair(ctx, tx, "tenant", code)
				return err
			})
			return token, d, err
		}

		var other string
		require.NoError(t, inTx(at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			other, err = svc.NewPairingCode(ctx, tx, rbac.System("operator"), "operator", "Ops kiosk", "")
			return err
		}))
		_, _, err := pair(at, other)
		require.ErrorIs(t, err, devices.ErrInvalidCode, "a code made for another realm")
		_, _, err = pair(at.Add(devices.CodeTTL), code)
		require.ErrorIs(t, err, devices.ErrInvalidCode, "expired")
		token, d, err := pair(at.Add(time.Minute), strings.ToLower(code))
		require.NoError(t, err, "codes are case-insensitive")
		_, _, err = pair(at.Add(time.Minute), code)
		require.ErrorIs(t, err, devices.ErrInvalidCode, "single use")

		p, err := resolve(at, "tenant", token)
		require.NoError(t, err)
		assert.Equal(t, rbac.SubjectDevice, p.Kind())
		assert.Equal(t, d.ID.UUID(), p.Subject())
		assert.True(t, p.Can(sell), "the app turned the scope into grants")
		_, err = resolve(at, "operator", token)
		require.ErrorIs(t, err, devices.ErrInvalidToken, "another realm")

		var rotated string
		require.NoError(t, inTx(at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			if _, err := svc.Rotate(ctx, tx, "operator", d.ID, time.Minute); !errors.Is(err, devices.ErrNotFound) {
				return fmt.Errorf("rotating from another realm: %w", err)
			}
			rotated, err = svc.Rotate(ctx, tx, "tenant", d.ID, 10*time.Minute)
			return err
		}))
		_, err = resolve(at.Add(5*time.Minute), "tenant", token)
		require.NoError(t, err, "the old secret works within the grace window")
		_, err = resolve(at.Add(11*time.Minute), "tenant", token)
		require.ErrorIs(t, err, devices.ErrInvalidToken, "and not after it")
		_, err = resolve(at.Add(11*time.Minute), "tenant", rotated)
		require.NoError(t, err)

		var unbounded string
		require.NoError(t, inTx(at.Add(11*time.Minute), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			unbounded, err = svc.Rotate(ctx, tx, "tenant", d.ID, 1000*time.Hour)
			return err
		}))
		_, err = resolve(at.Add(11*time.Minute+devices.MaxGrace+time.Second), "tenant", rotated)
		require.ErrorIs(t, err, devices.ErrInvalidToken, "grace is clamped to a day")

		require.NoError(t, inTx(at, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			if err := svc.Revoke(ctx, tx, "operator", d.ID); !errors.Is(err, devices.ErrNotFound) {
				return fmt.Errorf("revoking from another realm: %w", err)
			}
			return svc.Revoke(ctx, tx, "tenant", d.ID)
		}))
		_, err = resolve(at.Add(12*time.Minute), "tenant", unbounded)
		require.ErrorIs(t, err, devices.ErrInvalidToken, "revoked")
	})
}

func FuzzParse(f *testing.F) {
	id := ids.New().String()
	secret := strings.Repeat("A", 43)
	for _, seed := range []string{id + "." + secret, id, "." + secret, id + "." + secret + ".x", strings.ToUpper(id) + "." + secret, "x.y", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, hash, err := devices.Parse(raw)
		if err != nil {
			return
		}
		assert.Len(t, hash, 32)
		assert.True(t, strings.HasPrefix(raw, got.String()+"."))
	})
}
