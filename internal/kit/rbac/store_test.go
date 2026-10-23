package rbac_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var catalogue = rbac.NewCatalogue(
	rbac.Perm{Code: manage, Area: "Access", Label: "Manage access"},
	rbac.Perm{Code: read, Area: "Notes", Label: "Read notes"},
	rbac.Perm{Code: write, Area: "Notes", Label: "Write notes"},
)

func TestSetupAndLoader(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		rec := audit.New(audit.Options{})
		realm := "r" + ids.New().String()[24:]
		access := rbac.NewAccess(rec, rbac.Policy{AccessManage: manage}, map[string]*rbac.Catalogue{realm: catalogue})
		system := rbac.System(realm)
		builtins := []rbac.Builtin{
			{Code: "admin", Name: "Administrator", Permissions: []rbac.Code{manage, read, write}},
			{Code: "editor", Name: "Editor", Permissions: []rbac.Code{read, write}},
		}
		inTx := func(fn func(ctx context.Context, tx db.Tx[db.Plain]) error) {
			t.Helper()
			require.NoError(t, db.InTx(ctx, e.DB(), fn))
		}

		var editor rbac.Role
		inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			created, err := access.Setup(ctx, tx, realm, builtins)
			require.NoError(t, err)
			assert.Len(t, created, 2)
			editor = created[1]
			_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE roles SET name = ? WHERE id = ?"), "Renamed", editor.ID)
			require.NoError(t, err)
			_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM role_permissions WHERE role_id = ? AND permission = ?"), editor.ID, string(write))
			return err
		})

		inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			created, err := access.Setup(ctx, tx, realm, builtins)
			require.NoError(t, err)
			assert.Empty(t, created, "a second setup creates nothing")
			again, err := rbac.RoleByCode(ctx, tx, realm, "editor")
			require.NoError(t, err)
			assert.Equal(t, "Renamed", again.Name, "setup never overwrites an edited role")
			assert.Equal(t, []rbac.Code{read}, again.Permissions)
			return nil
		})

		var alice users.User
		var admin rbac.Role
		svc := users.NewService(rec, access)
		inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			alice, err = svc.Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test", Name: "Alice"})
			require.NoError(t, err)
			admin, err = rbac.RoleByCode(ctx, tx, realm, "admin")
			require.NoError(t, err)
			require.NoError(t, access.Grant(ctx, tx, system, rbac.UserRole{UserID: alice.ID, RoleID: editor.ID, Scope: &branch}))
			require.NoError(t, access.Grant(ctx, tx, system, rbac.UserRole{UserID: alice.ID, RoleID: admin.ID}))
			_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)"), admin.ID, "retired.permission")
			return err
		})
		for _, again := range []rbac.UserRole{
			{UserID: alice.ID, RoleID: editor.ID, Scope: &branch},
			{UserID: alice.ID, RoleID: admin.ID},
		} {
			err := db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return access.Grant(ctx, tx, system, again)
			})
			require.ErrorIs(t, err, rbac.ErrAlreadyGranted, "a grant is unique, scoped or not")
		}

		inTx(func(ctx context.Context, tx db.Tx[db.Plain]) error {
			p, err := rbac.NewLoader(realm, catalogue).Load(ctx, tx, alice.ID)
			require.NoError(t, err)
			assert.Equal(t, []rbac.Code{manage, read, write}, p.Permissions(), "the unknown code is ignored")
			assert.True(t, p.CanIn(read, branch))

			other, err := rbac.NewLoader("elsewhere", catalogue).Load(ctx, tx, alice.ID)
			require.NoError(t, err)
			assert.Empty(t, other.Permissions(), "roles of another realm do not count")

			_, err = tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "UPDATE users SET status = ? WHERE id = ?"), string(users.Disabled), alice.ID)
			require.NoError(t, err)
			_, err = rbac.NewLoader(realm, catalogue).Load(ctx, tx, alice.ID)
			assert.ErrorIs(t, err, rbac.ErrUserDisabled)
			return nil
		})
	})
}
