package notes_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
	"github.com/PuckxPuck/keel/internal/modules/notes"
)

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// needs is the permission each operation asks for: reading, writing, or archiving.
var needs = map[string]rbac.Code{
	"listNotes": notes.PermRead, "listNoteChanges": notes.PermRead, "exportNotes": notes.PermRead, "getNote": notes.PermRead,
	"createNote": notes.PermWrite, "updateNote": notes.PermWrite, "deleteNote": notes.PermWrite, "attachNoteFile": notes.PermWrite,
	"archiveNote": notes.PermArchive,
}

var bodies = map[string]string{
	"createNote": `{"title":"x"}`, "updateNote": `{"version":1}`,
	"attachNoteFile": `{"fileId":"` + ids.New().String() + `","version":1}`,
}

// Through the app: each operation needs exactly its permission, so holding the other notes permissions
// changes nothing. Without a database an allowed call reaches the handler and answers 503.
func TestOperations_NeedTheirPermission(t *testing.T) {
	cfg, err := app.LoadConfig([]string{
		"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080",
		"APP_SESSION_KEYS=a2VlbC10ZXN0LXNpZ25pbmcta2V5LW9mLTMyLWJ5dGVzIQ==",
	})
	require.NoError(t, err)
	ctx := logx.WithLogger(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	built, err := app.Build(ctx, cfg, app.Deps{})
	require.NoError(t, err)
	user := users.ID(ids.New())
	walked := 0
	built.Realms.Each(func(r realm.Realm, api huma.API) {
		call := func(op *huma.Operation, perms ...rbac.Code) int {
			var grants []rbac.Grant
			for _, p := range perms {
				grants = append(grants, rbac.Grant{Perm: p})
			}
			as := rbac.WithPrincipal(ctx, rbac.NewPrincipal(user, r.Name, grants...))
			req := httptest.NewRequestWithContext(as, op.Method, pathParam.ReplaceAllString(op.Path, ids.New().String()), strings.NewReader(bodies[op.OperationID]))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			built.Handler.ServeHTTP(rec, req)
			return rec.Code
		}
		for _, op := range httpx.Operations(api) {
			if !slices.Contains(op.Tags, "notes") {
				continue
			}
			walked++
			want, ok := needs[op.OperationID]
			require.True(t, ok, "%s has no expected permission", op.OperationID)
			need, ok := rbac.NeedOf(op)
			require.True(t, ok, op.OperationID)
			assert.Equal(t, []rbac.Code{want}, need.Perms(), op.OperationID)
			var others []rbac.Code
			for _, p := range []rbac.Code{notes.PermRead, notes.PermWrite, notes.PermArchive} {
				if p != want {
					others = append(others, p)
				}
			}
			assert.Equal(t, http.StatusForbidden, call(op, others...), "%s without %s", op.OperationID, want)
			assert.Equal(t, http.StatusServiceUnavailable, call(op, want), "%s with %s", op.OperationID, want)
		}
	})
	assert.Len(t, needs, walked)
}
