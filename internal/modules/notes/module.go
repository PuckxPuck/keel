package notes

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// Deps is what the module takes from the app's wiring: the realm that serves it and that realm's base
// path (for list links). Without a database its operations answer 503 (route:list, the OpenAPI export).
type Deps struct {
	Realm    string
	BasePath string
	DB       *db.DB
	Audit    *audit.Recorder
	Cursors  *paging.Keyset
	// Jobs is the queue serve runs, nil without a database: enqueue in the transaction that makes the
	// change, so the job exists only if the change commits.
	Jobs *jobs.Queue
	// Mail queues email in the caller's transaction; nil without a database.
	Mail *mail.Service
	// Files stores attachments; nil when APP_FILES_DRIVER is unset, and attaching answers 404.
	Files *files.Service
	// FeedRetention is how long deletes stay in the change feed (APP_FEED_TOMBSTONE_RETENTION).
	FeedRetention time.Duration
}

type Module struct {
	realm    string
	basePath string
	svc      *Service
}

// New panics on a Deps the app's configuration check should have refused (a feed retention of zero).
func New(d Deps) *Module {
	svc, err := NewService(d)
	if err != nil {
		panic(err)
	}
	return &Module{realm: d.Realm, basePath: d.BasePath, svc: svc}
}

// Service is the module's service, for tests and other modules' wiring.
func (m *Module) Service() *Service { return m.svc }

func (m *Module) Permissions(realm string) []rbac.Perm {
	if realm != m.realm {
		return nil
	}
	return permissions
}

var tags = []string{"notes"}

// publicSince is when the notes operations marked httpx.Public joined the public API.
const publicSince = "2026-10-23"

func (m *Module) Register(realm string, api huma.API) {
	if realm != m.realm {
		return
	}
	h := handlers{svc: m.svc, basePath: m.basePath}
	read, write := ratelimit.Class(ratelimit.ClassAPIRead), ratelimit.Class(ratelimit.ClassAPIWrite)
	public := httpx.Public(publicSince)
	op := func(id, method, path, summary string, errs ...int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tags, Errors: errs}
	}
	httpx.Register(api, op("listNotes", http.MethodGet, "/notes", "List notes", http.StatusBadRequest),
		h.list, rbac.Requires(PermRead), read, public)
	httpx.Register(api, op("listNoteChanges", http.MethodGet, "/notes/changes", "Changes to notes after a sync token, deletes included",
		http.StatusBadRequest, http.StatusGone), h.changes, rbac.Requires(PermRead), read)
	httpx.Register(api, exportOperation(op("exportNotes", http.MethodGet, "/notes/export.xlsx", "Download the notes a filter selects as a spreadsheet",
		http.StatusBadRequest, http.StatusUnprocessableEntity)),
		servedByHandler[exportInput], rbac.Requires(PermRead), ratelimit.Class(ratelimit.ClassHeavy), httpx.Serve(h.export()))
	httpx.Register(api, op("getNote", http.MethodGet, "/notes/{noteId}", "Get a note", http.StatusNotFound),
		h.get, rbac.Requires(PermRead), read, public)
	create := op("createNote", http.MethodPost, "/notes", "Create a note; a clientId already stored answers 200 with that note",
		http.StatusConflict, http.StatusUnprocessableEntity)
	create.DefaultStatus = http.StatusCreated
	httpx.Register(api, create, h.create, rbac.Requires(PermWrite), write, idempotency.Required(), public)
	httpx.Register(api, op("updateNote", http.MethodPatch, "/notes/{noteId}", "Change a note",
		http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity), h.update, rbac.Requires(PermWrite), write)
	httpx.Register(api, op("deleteNote", http.MethodDelete, "/notes/{noteId}", "Delete a note and its attachment", http.StatusNotFound),
		h.delete, rbac.Requires(PermWrite), write)
	httpx.Register(api, op("archiveNote", http.MethodPost, "/notes/{noteId}/archive", "Archive a note; it can no longer be changed",
		http.StatusNotFound, http.StatusConflict), h.archive, rbac.Requires(PermArchive), write)
	httpx.Register(api, op("attachNoteFile", http.MethodPost, "/notes/{noteId}/attachment",
		"Make an uploaded note-attachment file the note's attachment, replacing the one it had",
		http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity), h.attach, rbac.Requires(PermWrite), write)
}

func (m *Module) Mapper(err error) (*problem.Problem, bool) { return mapError(err) }

func (m *Module) Jobs(q *jobs.Queue) {
	q.Handle(KindIndex, jobs.Typed(m.runIndex))
}

func (m *Module) Commands(_ func(ctx context.Context) (*db.DB, func(), error)) []cli.Command {
	return nil
}
