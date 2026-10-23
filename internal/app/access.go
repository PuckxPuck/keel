package app

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

const RealmTenant = "tenant"

const (
	PermAccessManage  rbac.Code = "access.manage"
	PermUsersManage   rbac.Code = "users.manage"
	PermDevicesManage rbac.Code = "devices.manage"
)

var tenantCatalogue = rbac.NewCatalogue(append(append([]rbac.Perm{
	{
		Code: PermAccessManage, Area: "Access", Label: "Manage roles and access",
		Description: "Create and edit roles and give or take them from people", Sensitive: true,
	},
	{
		Code: PermUsersManage, Area: "Users", Label: "Manage users",
		Description: "Invite, edit, disable and enable users", Sensitive: true,
	},
	{
		Code: PermDevicesManage, Area: "Devices", Label: "Manage devices",
		Description: "Pair shared devices, rotate their secrets and revoke them", Sensitive: true,
	},
}, apiKeyPerms...), modulePermissions(RealmTenant)...)...)

// Policy keeps the access-management permission from losing its last holder or role.
var Policy = rbac.Policy{AccessManage: PermAccessManage}

// NewAccess is the app's one writer of roles and grants, and the guard users.Service needs. Pass the
// sessions as a hook so taking a user's last role ends their sessions.
func NewAccess(rec *audit.Recorder, opts ...rbac.AccessOption) *rbac.Access {
	catalogues := map[string]*rbac.Catalogue{RealmOperator: operatorCatalogue}
	for _, r := range realms() {
		catalogues[r.Name] = r.Catalogue
	}
	return rbac.NewAccess(rec, Policy, catalogues, opts...)
}

// realms are the app's realms. The tenant realm has no hosts, so it answers on every host until the
// operator realm claims one (tenancy).
func realms() []realm.Realm {
	return []realm.Realm{
		{Name: RealmTenant, BasePath: BasePath, Catalogue: tenantCatalogue},
	}
}

// configuredRealms are the realms with hosts and session settings from cfg.
func configuredRealms(cfg Config) []realm.Realm {
	blocks := map[string]RealmConfig{RealmTenant: cfg.Realm.Tenant}
	out := realms()
	for i, r := range out {
		out[i] = blocks[r.Name].apply(r, cfg.Session)
		out[i].Loader = rbac.NewLoader(r.Name, r.Catalogue)
	}
	if op, ok := configuredOperator(cfg); ok {
		out = append(out, op)
	}
	return out
}

// builtinRoles are created by `app setup` once per realm and never overwritten.
var builtinRoles = map[string][]rbac.Builtin{
	RealmTenant: {
		{Code: "admin", Name: "Administrator", Permissions: append(append([]rbac.Code{PermAccessManage, PermUsersManage, PermDevicesManage},
			permCodes(apiKeyPerms)...), moduleCodes(RealmTenant)...)},
	},
}

// taggedOperations are tenant-realm operations a build tag adds (deploytest's hold route); none in a
// release build.
var taggedOperations []func(huma.API)

// operations registers each realm's operations.
func operations(w *wiring) map[string][]func(huma.API) {
	tenant := []func(huma.API){registerPing, w.registerAuth, w.registerOIDC, w.registerPasskeys, w.registerDevices, w.registerAPIKeys, w.registerFiles, w.registerTenancy}
	return withModules(w, map[string][]func(huma.API){
		RealmTenant:   append(tenant, taggedOperations...),
		RealmOperator: {registerPing, w.registerAuth, w.registerOperator},
	})
}
