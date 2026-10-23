package app

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/devices"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

type pairingCodeInput struct {
	Body struct {
		Name  string `json:"name" minLength:"1" maxLength:"200"`
		Scope string `json:"scope,omitempty" maxLength:"200" doc:"What the device may do; the app maps it to permissions"`
	}
}

type PairingCode struct {
	Code      string    `json:"code" doc:"Enter on the device within ten minutes; works once"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type pairInput struct {
	Body struct {
		Code string `json:"code" minLength:"1" maxLength:"32"`
	}
}

// Paired is the new device and its bearer token, shown once.
type Paired struct {
	Token  string         `json:"token"`
	Device devices.Device `json:"device"`
}

type listDevicesInput struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"100" default:"50"`
	Cursor string `query:"cursor" maxLength:"1024"`
	Sort   string `query:"sort" enum:"createdAt,-createdAt" default:"createdAt"`
}

type deviceIDInput struct {
	DeviceID string `path:"deviceId" format:"uuid"`
}

type rotateDeviceInput struct {
	DeviceID string `path:"deviceId" format:"uuid"`
	Body     struct {
		GraceSeconds *int `json:"graceSeconds,omitempty" minimum:"0" maximum:"86400" doc:"How long the old token keeps working; 300 when left out"`
	}
}

type DeviceToken struct {
	Token string `json:"token" doc:"Shown once"`
}

var tagDevices = []string{"devices"}

const defaultGrace = 5 * time.Minute

func (w *wiring) registerDevices(api huma.API) {
	manage := rbac.Requires(PermDevicesManage)
	write, read := ratelimit.Class(ratelimit.ClassAPIWrite), ratelimit.Class(ratelimit.ClassAPIRead)
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tagDevices}
	}
	httpx.Register(api, op("createDevicePairingCode", http.MethodPost, "/devices/pairing-codes", "Make a code that pairs one device"),
		w.createPairingCode, manage, write)
	httpx.Register(api, op("pairDevice", http.MethodPost, "/devices/pair", "Trade a pairing code for a device token"),
		w.pairDevice, rbac.Public(), authClass)
	httpx.Register(api, op("listDevices", http.MethodGet, "/devices", "List the realm's devices"), w.listDevices, manage, read)
	httpx.Register(api, op("rotateDevice", http.MethodPost, "/devices/{deviceId}/rotate", "Give a device a new token"),
		w.rotateDevice, manage, write)
	httpx.Register(api, op("revokeDevice", http.MethodDelete, "/devices/{deviceId}", "Stop a device's tokens at once"),
		w.revokeDevice, manage, write)
}

func (w *wiring) createPairingCode(ctx context.Context, in *pairingCodeInput) (*httpx.One[PairingCode], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return nil, auth.ErrNoSession
	}
	var out PairingCode
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out.Code, err = w.devices.NewPairingCode(ctx, tx, p, httpx.Realm(ctx), in.Body.Name, in.Body.Scope)
		out.ExpiresAt = now(ctx).Add(devices.CodeTTL)
		return err
	})
	return one(out, err)
}

// pairDevice counts every redemption by address before the code is looked up (D31) and gives the
// attempt back when the code worked.
func (w *wiring) pairDevice(ctx context.Context, in *pairInput) (*httpx.One[Paired], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	addr, _ := auth.Address(ctx)
	limit := auth.Limit{Key: auth.Key("device-pair-address", addr), Rate: pairPerAddress}
	if err := w.failures.Attempt(ctx, limit); err != nil {
		return nil, err
	}
	var out Paired
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out.Token, out.Device, err = w.devices.Pair(ctx, tx, httpx.Realm(ctx), in.Body.Code)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := w.failures.Succeeded(ctx, limit); err != nil {
		logx.From(ctx).Warn("refund pairing attempt", "error", err)
	}
	return httpx.OneOf(out), nil
}

func (w *wiring) listDevices(ctx context.Context, in *listDevicesInput) (*httpx.List[devices.Device], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	sort, err := devices.Sorts.Resolve(in.Sort, "createdAt")
	if err != nil {
		return nil, err
	}
	realmName := httpx.Realm(ctx)
	after, err := w.cursors.After(in.Cursor, sort, realmName)
	if err != nil {
		return nil, err
	}
	var page paging.Page[devices.Device]
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		rows, err := devices.List(ctx, tx, realmName, after, sort, in.Limit)
		if err != nil {
			return err
		}
		page, err = paging.Trim(rows, in.Limit, sort, realmName, w.cursors, func(d devices.Device) devices.Device { return d })
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	self := &url.URL{Path: BasePath + "/devices", RawQuery: url.Values{"limit": {strconv.Itoa(in.Limit)}, "sort": {in.Sort}}.Encode()}
	if page.Items == nil {
		page.Items = []devices.Device{}
	}
	return page.List(in.Limit, self), nil
}

func (w *wiring) rotateDevice(ctx context.Context, in *rotateDeviceInput) (*httpx.One[DeviceToken], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	id, err := devices.ParseID(in.DeviceID)
	if err != nil {
		return nil, devices.ErrNotFound
	}
	grace := defaultGrace
	if in.Body.GraceSeconds != nil {
		grace = time.Duration(*in.Body.GraceSeconds) * time.Second
	}
	var out DeviceToken
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		out.Token, err = w.devices.Rotate(ctx, tx, httpx.Realm(ctx), id, grace)
		return err
	})
	return one(out, err)
}

func (w *wiring) revokeDevice(ctx context.Context, in *deviceIDInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	id, err := devices.ParseID(in.DeviceID)
	if err != nil {
		return nil, devices.ErrNotFound
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		return w.devices.Revoke(ctx, tx, httpx.Realm(ctx), id)
	}))
}
