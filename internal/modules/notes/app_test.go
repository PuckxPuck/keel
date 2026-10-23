//go:build !notenancy

package notes_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/xlsx"
	"github.com/PuckxPuck/keel/internal/modules/notes"
)

const (
	sharedHost = "app.example.test"
	acmeHost   = "acme.tenants.example.test"
	globexHost = "globex.tenants.example.test"
	password   = "violet-otter-harbour"
)

// notesApp is the whole app on a database with tenancy, with mail recorded and files on a temp dir.
type notesApp struct {
	t     *testing.T
	d     *testdb.TenancyDB
	cfg   app.Config
	deps  app.Deps
	h     http.Handler
	queue *jobs.Queue
	sent  *mail.Recorder
}

func newNotesApp(t *testing.T) *notesApp {
	t.Helper()
	d := testdb.Tenancy(t)
	cfg, err := app.LoadConfig([]string{
		"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", "APP_PASSWORD_ARGON2=m=64,t=1,p=1",
		"APP_SESSION_KEYS=a2VlbC10ZXN0LXNpZ25pbmcta2V5LW9mLTMyLWJ5dGVzIQ==",
		"APP_TENANCY_HOST_SUFFIX=.tenants.example.test", "APP_FILES_DRIVER=local", "APP_FILES_ROOT=" + t.TempDir(),
		"APP_JOBS_POLL=50ms", "APP_JOBS_SHUTDOWN_GRACE=0s",
	})
	require.NoError(t, err)
	a := &notesApp{t: t, d: d, cfg: cfg, sent: &mail.Recorder{}}
	a.deps = app.Deps{DB: d.DB, Operator: d.Operator, Tenancy: true, Mailer: a.sent}
	require.NoError(t, app.CheckTenancy(t.Context(), a.deps))
	built, err := app.Build(t.Context(), cfg, a.deps)
	require.NoError(t, err)
	a.h, a.queue = built.Handler, built.Queue
	_, err = app.Setup(t.Context(), a.deps, audit.New(audit.Options{}))
	require.NoError(t, err)
	return a
}

type request struct {
	method, host, path, body string
	cookie                   *http.Cookie
	header                   http.Header
}

func (a *notesApp) do(r request) *httptest.ResponseRecorder {
	a.t.Helper()
	ctx := logx.WithLogger(a.t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequestWithContext(ctx, r.method, r.path, strings.NewReader(r.body))
	req.Host = r.host
	for k, v := range r.header {
		req.Header[k] = v
	}
	if r.body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

// person makes a user with a password who belongs to no tenant yet.
func (a *notesApp) person(name string) string {
	a.t.Helper()
	email := name + "@example.test"
	_, invite, err := app.CreateUser(a.t.Context(), a.cfg, a.deps, email, name, true)
	require.NoError(a.t, err)
	rec := a.do(request{method: http.MethodPost, host: sharedHost, path: "/api/v1/auth/invites/accept", body: `{"token":"` + invite + `","password":"` + password + `"}`})
	require.Equal(a.t, http.StatusNoContent, rec.Code, rec.Body.String())
	return email
}

func (a *notesApp) tenant(slug, owner string) tenancy.Tenant {
	a.t.Helper()
	tn, err := app.CreateTenant(a.t.Context(), a.cfg, a.deps, tenancy.NewTenant{Slug: slug, Name: slug}, owner)
	require.NoError(a.t, err)
	return tn
}

func (a *notesApp) signIn(host, email string) *http.Cookie {
	a.t.Helper()
	rec := a.do(request{method: http.MethodPost, host: host, path: "/api/v1/auth/sign-in", body: `{"email":"` + email + `","password":"` + password + `"}`})
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			return c
		}
	}
	require.Failf(a.t, "no session", "%s: %s", email, rec.Body.String())
	return nil
}

func (a *notesApp) createNote(host string, cookie *http.Cookie, body string) map[string]any {
	a.t.Helper()
	rec := a.do(request{
		method: http.MethodPost, host: host, path: "/api/v1/notes", body: body, cookie: cookie,
		header: http.Header{"Idempotency-Key": {ids.New().String()}},
	})
	require.Equal(a.t, http.StatusCreated, rec.Code, rec.Body.String())
	return data(a.t, rec)
}

func data(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return body.Data
}

// A member holding only notes.write cannot read or archive notes, nor download their attachments; the
// owner can. Another tenant's owner gets 404 for every note operation and for the attachment.
func TestNotes_PermissionsTenantsAndAttachments(t *testing.T) {
	a := newNotesApp(t)
	ann, bob, carol := a.person("ann"), a.person("bob"), a.person("carol")
	acme := a.tenant("acme", ann)
	a.tenant("globex", bob)
	rec := audit.New(audit.Options{})
	err := db.InTx(db.WithTenant(t.Context(), acme.ID.UUID()), a.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		_, err := app.NewAccess(rec).CreateRole(ctx, tx, rbac.System(app.RealmTenant),
			rbac.NewRole{Code: "writer", Name: "Writer", Permissions: []rbac.Code{notes.PermWrite}})
		return err
	})
	require.NoError(t, err)
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "writer", carol, "acme"))
	annIn, carolIn, bobIn := a.signIn(acmeHost, ann), a.signIn(acmeHost, carol), a.signIn(globexHost, bob)

	note := a.createNote(acmeHost, annIn, `{"title":"Shift handover","body":"Keys in the drawer"}`)
	noteID := note["id"].(string)
	upload := a.do(request{
		method: http.MethodPost, host: acmeHost, path: "/api/v1/files/" + notes.AttachmentKind, body: "handover notes",
		cookie: annIn, header: http.Header{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {`attachment; filename="handover.txt"`}},
	})
	require.Equal(t, http.StatusCreated, upload.Code, upload.Body.String())
	fileID := data(t, upload)["id"].(string)
	attached := a.do(request{
		method: http.MethodPost, host: acmeHost, path: "/api/v1/notes/" + noteID + "/attachment",
		body: `{"fileId":"` + fileID + `","version":1}`, cookie: annIn,
	})
	require.Equal(t, http.StatusOK, attached.Code, attached.Body.String())
	assert.Equal(t, "handover.txt", data(t, attached)["attachment"].(map[string]any)["name"])

	download := a.do(request{method: http.MethodGet, host: acmeHost, path: "/api/v1/files/" + fileID, cookie: annIn})
	require.Equal(t, http.StatusOK, download.Code, download.Body.String())
	assert.Equal(t, "handover notes", download.Body.String())

	refused := []struct {
		name   string
		r      request
		status int
	}{
		{"writer reads a note", request{method: http.MethodGet, host: acmeHost, path: "/api/v1/notes/" + noteID, cookie: carolIn}, http.StatusForbidden},
		{"writer archives", request{method: http.MethodPost, host: acmeHost, path: "/api/v1/notes/" + noteID + "/archive", cookie: carolIn}, http.StatusForbidden},
		{"writer downloads the attachment", request{method: http.MethodGet, host: acmeHost, path: "/api/v1/files/" + fileID, cookie: carolIn}, http.StatusNotFound},
		{"other tenant reads", request{method: http.MethodGet, host: globexHost, path: "/api/v1/notes/" + noteID, cookie: bobIn}, http.StatusNotFound},
		{"other tenant edits", request{method: http.MethodPatch, host: globexHost, path: "/api/v1/notes/" + noteID, body: `{"version":2,"title":"Mine"}`, cookie: bobIn}, http.StatusNotFound},
		{"other tenant archives", request{method: http.MethodPost, host: globexHost, path: "/api/v1/notes/" + noteID + "/archive", cookie: bobIn}, http.StatusNotFound},
		{"other tenant attaches", request{method: http.MethodPost, host: globexHost, path: "/api/v1/notes/" + noteID + "/attachment", body: `{"fileId":"` + fileID + `","version":2}`, cookie: bobIn}, http.StatusNotFound},
		{"other tenant deletes", request{method: http.MethodDelete, host: globexHost, path: "/api/v1/notes/" + noteID, cookie: bobIn}, http.StatusNotFound},
		{"other tenant downloads", request{method: http.MethodGet, host: globexHost, path: "/api/v1/files/" + fileID, cookie: bobIn}, http.StatusNotFound},
	}
	for _, tt := range refused {
		got := a.do(tt.r)
		assert.Equal(t, tt.status, got.Code, "%s: %s", tt.name, got.Body.String())
	}

	after := a.do(request{method: http.MethodGet, host: acmeHost, path: "/api/v1/notes/" + noteID, cookie: annIn})
	require.Equal(t, http.StatusOK, after.Code)
	assert.Equal(t, "Shift handover", data(t, after)["title"], "nothing the refused calls tried changed the note")
	assert.Equal(t, "active", data(t, after)["status"])
}

// Creating a note queues its index job and archiving it mails the author; once archived it cannot be
// edited. The export is a workbook kit/xlsx reads back, with a formula-like title kept as text.
func TestNotes_IndexArchiveMailAndExport(t *testing.T) {
	a := newNotesApp(t)
	ann := a.person("ann")
	a.tenant("acme", ann)
	annIn := a.signIn(acmeHost, ann)

	title := `=HYPERLINK("https://example.test","open")`
	note := a.createNote(acmeHost, annIn, `{"title":`+quote(title)+`,"body":"three short words"}`)
	noteID := note["id"].(string)
	archived := a.do(request{method: http.MethodPost, host: acmeHost, path: "/api/v1/notes/" + noteID + "/archive", cookie: annIn})
	require.Equal(t, http.StatusOK, archived.Code, archived.Body.String())
	assert.Equal(t, "archived", data(t, archived)["status"])
	edit := a.do(request{method: http.MethodPatch, host: acmeHost, path: "/api/v1/notes/" + noteID, body: `{"version":2,"title":"Changed"}`, cookie: annIn})
	assert.Equal(t, http.StatusConflict, edit.Code, edit.Body.String())

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- a.queue.Run(ctx) }()
	require.Eventually(t, func() bool {
		got := a.do(request{method: http.MethodGet, host: acmeHost, path: "/api/v1/notes/" + noteID, cookie: annIn})
		var body struct {
			Data struct {
				WordCount int `json:"wordCount"`
			} `json:"data"`
		}
		return json.Unmarshal(got.Body.Bytes(), &body) == nil && body.Data.WordCount == 3 && len(a.sent.Messages()) == 1
	}, 10*time.Second, 20*time.Millisecond, "the index job ran and the archive notice was sent")
	cancel()
	require.NoError(t, <-stopped)
	notice := a.sent.Messages()[0]
	require.Len(t, notice.To, 1)
	assert.Contains(t, notice.To[0], "ann@example.test")
	assert.Contains(t, notice.Text, title)

	export := a.do(request{method: http.MethodGet, host: acmeHost, path: "/api/v1/notes/export.xlsx?status=archived", cookie: annIn})
	require.Equal(t, http.StatusOK, export.Code, export.Body.String())
	book, err := xlsx.NewReader(bytes.NewReader(export.Body.Bytes()), xlsx.Limits{})
	require.NoError(t, err)
	defer func() { _ = book.Close() }()
	rows, err := book.Rows("Notes")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var titles []string
	for rows.Next() {
		titles = append(titles, rows.Row().String(0))
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"Title", "'" + title}, titles)
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
