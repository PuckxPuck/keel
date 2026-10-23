package testdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The app role is refused when any chain of memberships reaches a role around row-level security, and
// setup takes away whatever memberships it was given.
func TestAppRole_MembershipsAreCheckedAndRevoked(t *testing.T) {
	d := Tenancy(t)
	tests := []struct {
		name, attrs, member string
		wantErr             bool
	}{
		{name: "no memberships", attrs: "nobypassrls"},
		{name: "a member of a role that bypasses row-level security, two steps away", attrs: "nobypassrls", member: "bypassrls", wantErr: true},
		{name: "a member of a superuser", attrs: "nobypassrls", member: "superuser", wantErr: true},
		{name: "a member of the owner role", attrs: "nobypassrls", member: "owner", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := d.TempRole(t, tt.attrs)
			switch tt.member {
			case "":
			case "owner":
				d.Admin(t, "GRANT "+quote(d.srv.roles.owner)+" TO "+quote(role))
			default:
				middle := d.TempRole(t, "nobypassrls")
				d.Admin(t, "GRANT "+quote(d.TempRole(t, tt.member))+" TO "+quote(middle), "GRANT "+quote(middle)+" TO "+quote(role))
			}
			err := d.srv.refuseEscapingRole(t.Context(), d.AsRole(t, role).SQL())
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)

			conn, err := d.srv.admin.Conn(t.Context())
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			require.NoError(t, revokeMemberships(t.Context(), conn, role))
			assert.NoError(t, d.srv.refuseEscapingRole(t.Context(), d.AsRole(t, role).SQL()), "setup revokes them")
		})
	}
}
