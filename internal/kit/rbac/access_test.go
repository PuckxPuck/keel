package rbac_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const (
	manage rbac.Code = "access.manage"
	read   rbac.Code = "notes.read"
	write  rbac.Code = "notes.write"
)

var (
	branch = rbac.Scope{Type: "branch", ID: uuid.MustParse("0192f5a0-0000-7000-8000-000000000001")}
	other  = rbac.Scope{Type: "branch", ID: uuid.MustParse("0192f5a0-0000-7000-8000-000000000002")}
)

// world is one realm with a built-in role, three custom roles and four users; alice and dave are
// administrators.
type world struct {
	realm                 string
	access                *rbac.Access
	users                 *users.Service
	builtin               rbac.Role
	admin, editor, viewer rbac.Role
	alice, bob, carol     users.User
	dave                  users.User
}

func newWorld(t *testing.T, e *testdb.Engine) *world {
	t.Helper()
	rec := audit.New(audit.Options{})
	w := &world{realm: "r" + ids.New().String()[24:]}
	w.access = rbac.NewAccess(rec, rbac.Policy{AccessManage: manage}, map[string]*rbac.Catalogue{w.realm: catalogue, "elsewhere": catalogue})
	w.users = users.NewService(rec, w.access)
	require.NoError(t, db.InTx(t.Context(), e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
		builtins, err := w.access.Setup(ctx, tx, w.realm, []rbac.Builtin{{Code: "reader", Name: "Reader", Permissions: []rbac.Code{read}}})
		require.NoError(t, err)
		w.builtin = builtins[0]
		for _, r := range []struct {
			role  *rbac.Role
			code  string
			perms []rbac.Code
		}{{&w.admin, "admin", []rbac.Code{manage, read, write}}, {&w.editor, "editor", []rbac.Code{read, write}}, {&w.viewer, "viewer", []rbac.Code{read}}} {
			*r.role, err = w.access.CreateRole(ctx, tx, rbac.System(w.realm), rbac.NewRole{Code: r.code, Name: r.code, Permissions: r.perms})
			require.NoError(t, err)
		}
		for _, u := range []*users.User{&w.alice, &w.bob, &w.carol, &w.dave} {
			*u, err = w.users.Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"})
			require.NoError(t, err)
		}
		for _, u := range []users.User{w.alice, w.dave} {
			require.NoError(t, w.access.Grant(ctx, tx, rbac.System(w.realm), rbac.UserRole{UserID: u.ID, RoleID: w.admin.ID}))
		}
		return nil
	}))
	return w
}

func (w *world) as(u users.User, grants ...rbac.Grant) rbac.Principal {
	return rbac.NewPrincipal(u.ID, w.realm, grants...)
}

func everywhere(perms ...rbac.Code) []rbac.Grant {
	var out []rbac.Grant
	for _, p := range perms {
		out = append(out, rbac.Grant{Perm: p})
	}
	return out
}

var errStale = errors.New("stale")

func refusedRules(err error) []string {
	var refused *rbac.RefusedError
	if !errors.As(err, &refused) {
		return nil
	}
	var out []string
	for _, v := range refused.Violations {
		out = append(out, v.Rule)
	}
	return out
}

// Every access change is checked inside the kit against facts read in its transaction.
func TestAccess_Rules(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		tests := []struct {
			name      string
			change    func(ctx context.Context, tx db.Transaction, w *world) error
			wantErr   error
			wantRules []string
		}{
			{"an access manager grants a role whose permissions they hold", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.Grant(ctx, tx, w.as(w.alice, everywhere(manage, read, write)...), rbac.UserRole{UserID: w.bob.ID, RoleID: w.editor.ID})
			}, nil, nil},
			{"nobody grants to themselves", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.Grant(ctx, tx, w.as(w.alice, everywhere(manage, read, write)...), rbac.UserRole{UserID: w.alice.ID, RoleID: w.viewer.ID})
			}, nil, []string{rbac.RuleOwnRoles}},
			{"nobody grants a permission they lack", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.Grant(ctx, tx, w.as(w.alice, everywhere(manage, read)...), rbac.UserRole{UserID: w.bob.ID, RoleID: w.editor.ID})
			}, nil, []string{rbac.RuleExceedsActor}},
			{"a holder without access management may not grant", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.Grant(ctx, tx, w.as(w.alice, everywhere(read, write)...), rbac.UserRole{UserID: w.bob.ID, RoleID: w.viewer.ID})
			}, rbac.ErrForbidden, nil},
			{"a scoped manager grants within the scope", func(ctx context.Context, tx db.Transaction, w *world) error {
				actor := w.as(w.alice, rbac.Grant{Perm: manage, Scope: &branch}, rbac.Grant{Perm: read, Scope: &branch}, rbac.Grant{Perm: write, Scope: &branch})
				return w.access.Grant(ctx, tx, actor, rbac.UserRole{UserID: w.bob.ID, RoleID: w.editor.ID, Scope: &branch})
			}, nil, nil},
			{"a scoped manager grants nowhere else", func(ctx context.Context, tx db.Transaction, w *world) error {
				actor := w.as(w.alice, rbac.Grant{Perm: manage, Scope: &branch}, rbac.Grant{Perm: read, Scope: &branch})
				return w.access.Grant(ctx, tx, actor, rbac.UserRole{UserID: w.bob.ID, RoleID: w.viewer.ID, Scope: &other})
			}, rbac.ErrForbidden, nil},
			{"a role of another realm is not found", func(ctx context.Context, tx db.Transaction, w *world) error {
				actor := rbac.NewPrincipal(w.alice.ID, "elsewhere", everywhere(manage, read, write)...)
				return w.access.Grant(ctx, tx, actor, rbac.UserRole{UserID: w.bob.ID, RoleID: w.viewer.ID})
			}, rbac.ErrRoleNotFound, nil},
			{"the system grants across what it holds but not across realms", func(ctx context.Context, tx db.Transaction, w *world) error {
				if err := w.access.Grant(ctx, tx, rbac.System(w.realm), rbac.UserRole{UserID: w.bob.ID, RoleID: w.admin.ID}); err != nil {
					return err
				}
				return w.access.Grant(ctx, tx, rbac.System("elsewhere"), rbac.UserRole{UserID: w.carol.ID, RoleID: w.admin.ID})
			}, rbac.ErrRoleNotFound, nil},
			{"revoking one of two access managers is fine", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.Revoke(ctx, tx, w.as(w.alice, everywhere(manage)...), rbac.UserRole{UserID: w.dave.ID, RoleID: w.admin.ID})
			}, nil, nil},
			{"the last active access manager keeps the role", func(ctx context.Context, tx db.Transaction, w *world) error {
				if _, err := w.users.SetStatus(ctx, tx, rbac.System(w.realm), w.dave.ID, w.dave.Version, users.Disabled); err != nil {
					return err
				}
				return w.access.Revoke(ctx, tx, w.as(w.bob, everywhere(manage)...), rbac.UserRole{UserID: w.alice.ID, RoleID: w.admin.ID})
			}, nil, []string{rbac.RuleLastAccessUser}},
			{"a scoped holder does not count as an access manager", func(ctx context.Context, tx db.Transaction, w *world) error {
				if err := w.access.Grant(ctx, tx, rbac.System(w.realm), rbac.UserRole{UserID: w.carol.ID, RoleID: w.admin.ID, Scope: &branch}); err != nil {
					return err
				}
				if err := w.access.Revoke(ctx, tx, w.as(w.alice, everywhere(manage)...), rbac.UserRole{UserID: w.dave.ID, RoleID: w.admin.ID}); err != nil {
					return err
				}
				return w.access.Revoke(ctx, tx, w.as(w.carol, everywhere(manage)...), rbac.UserRole{UserID: w.alice.ID, RoleID: w.admin.ID})
			}, nil, []string{rbac.RuleLastAccessUser}},
			{"disabling the last active access manager is refused", func(ctx context.Context, tx db.Transaction, w *world) error {
				if _, err := w.users.SetStatus(ctx, tx, w.as(w.alice), w.dave.ID, w.dave.Version, users.Disabled); err != nil {
					return err
				}
				_, err := w.users.SetStatus(ctx, tx, w.as(w.alice), w.alice.ID, w.alice.Version, users.Disabled)
				return err
			}, nil, []string{rbac.RuleLastAccessUser}},
			{"adding a permission the actor lacks to a role is refused", func(ctx context.Context, tx db.Transaction, w *world) error {
				_, err := w.access.SetRolePermissions(ctx, tx, w.as(w.alice, everywhere(manage, read)...), w.viewer.ID, w.viewer.Version, []rbac.Code{read, write})
				return err
			}, nil, []string{rbac.RuleExceedsActor}},
			{"an unknown permission is refused", func(ctx context.Context, tx db.Transaction, w *world) error {
				_, err := w.access.SetRolePermissions(ctx, tx, w.as(w.alice, everywhere(manage, read)...), w.viewer.ID, w.viewer.Version, []rbac.Code{"notes.burn"})
				return err
			}, nil, []string{rbac.RuleUnknownPermission}},
			{"a role edit at an old version is stale", func(ctx context.Context, tx db.Transaction, w *world) error {
				_, err := w.access.SetRolePermissions(ctx, tx, w.as(w.alice, everywhere(manage, read)...), w.viewer.ID, w.viewer.Version+1, []rbac.Code{})
				return err
			}, errStale, nil},
			{"the only role carrying access management keeps it", func(ctx context.Context, tx db.Transaction, w *world) error {
				_, err := w.access.SetRolePermissions(ctx, tx, w.as(w.alice, everywhere(manage, read, write)...), w.admin.ID, w.admin.Version, []rbac.Code{read, write})
				return err
			}, nil, []string{rbac.RuleLastAccessUser, rbac.RuleLastAccessRole}},
			{"a built-in role's permissions do not change", func(ctx context.Context, tx db.Transaction, w *world) error {
				_, err := w.access.SetRolePermissions(ctx, tx, w.as(w.alice, everywhere(manage, read, write)...), w.builtin.ID, w.builtin.Version, []rbac.Code{read, write})
				return err
			}, rbac.ErrBuiltinRole, nil},
			{"a built-in role is not deleted", func(ctx context.Context, tx db.Transaction, w *world) error {
				return w.access.DeleteRole(ctx, tx, w.as(w.alice, everywhere(manage, read, write)...), w.builtin.ID, w.builtin.Version)
			}, rbac.ErrBuiltinRole, nil},
			{"deleting the role every manager holds is refused even when another role carries it", func(ctx context.Context, tx db.Transaction, w *world) error {
				actor := w.as(w.bob, everywhere(manage, read, write)...)
				if _, err := w.access.SetRolePermissions(ctx, tx, actor, w.editor.ID, w.editor.Version, []rbac.Code{manage, read, write}); err != nil {
					return err
				}
				return w.access.DeleteRole(ctx, tx, actor, w.admin.ID, w.admin.Version)
			}, nil, []string{rbac.RuleLastAccessUser}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := newWorld(t, e)
				err := db.InTx(t.Context(), e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
					return tt.change(ctx, tx, w)
				})
				var stale *occ.StaleError
				switch {
				case tt.wantRules != nil:
					assert.ElementsMatch(t, tt.wantRules, refusedRules(err), "%v", err)
				case errors.Is(tt.wantErr, errStale):
					require.ErrorAs(t, err, &stale)
				case tt.wantErr != nil:
					require.ErrorIs(t, err, tt.wantErr)
				default:
					require.NoError(t, err)
				}
			})
		}
	})
}

// Two managers removing each other at the same moment cannot both succeed.
func TestAccess_MutualRemovalLeavesOneManager(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		tests := []struct {
			name   string
			remove func(ctx context.Context, tx db.Transaction, w *world, actor, target users.User) error
		}{
			{"revoke", func(ctx context.Context, tx db.Transaction, w *world, actor, target users.User) error {
				return w.access.Revoke(ctx, tx, w.as(actor, everywhere(manage)...), rbac.UserRole{UserID: target.ID, RoleID: w.admin.ID})
			}},
			{"disable", func(ctx context.Context, tx db.Transaction, w *world, actor, target users.User) error {
				_, err := w.users.SetStatus(ctx, tx, w.as(actor), target.ID, target.Version, users.Disabled)
				return err
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := newWorld(t, e)
				errs := make(chan error, 2)
				var wg sync.WaitGroup
				for _, pair := range [][2]users.User{{w.alice, w.dave}, {w.dave, w.alice}} {
					wg.Go(func() {
						errs <- db.InTx(t.Context(), e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
							return tt.remove(ctx, tx, w, pair[0], pair[1])
						})
					})
				}
				wg.Wait()
				close(errs)
				var refused, ok int
				for err := range errs {
					switch {
					case err == nil:
						ok++
					case len(refusedRules(err)) > 0:
						refused++
					default:
						require.NoError(t, err)
					}
				}
				assert.Equal(t, 1, ok)
				assert.Equal(t, 1, refused)
			})
		}
	})
}
