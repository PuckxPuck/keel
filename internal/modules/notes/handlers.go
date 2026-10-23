package notes

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// NoteResource is a note as the API shows it; can says what the caller may do with it.
type NoteResource struct {
	ID         ID          `json:"id"`
	ClientID   *uuid.UUID  `json:"clientId,omitempty" format:"uuid"`
	Title      string      `json:"title"`
	Body       string      `json:"body"`
	Status     Status      `json:"status" enum:"active,archived"`
	ArchivedAt *time.Time  `json:"archivedAt,omitempty"`
	WordCount  *int        `json:"wordCount,omitempty" doc:"Counted shortly after the body changes"`
	Attachment *Attachment `json:"attachment,omitempty" doc:"Download it from /files/{fileId}"`
	Version    int32       `json:"version"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	CreatedBy  *users.ID   `json:"createdBy,omitempty"`
	Can        NoteCan     `json:"can"`
}

type NoteCan struct {
	Edit    bool `json:"edit"`
	Archive bool `json:"archive"`
	Delete  bool `json:"delete"`
}

type listInput struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"100" default:"50"`
	Cursor string `query:"cursor" maxLength:"1024"`
	Sort   string `query:"sort" enum:"title,-title,createdAt,-createdAt,updatedAt,-updatedAt" default:"-updatedAt"`
	Status string `query:"status" enum:"active,archived"`
	Q      string `query:"q" minLength:"2" maxLength:"100" doc:"Only notes whose title contains this, ignoring case"`
}

type changesInput struct {
	Since string `query:"since" maxLength:"1024" doc:"links.next of the last page applied; empty starts a full sync"`
	Limit int    `query:"limit" minimum:"1" maximum:"500" default:"100"`
}

type idInput struct {
	NoteID string `path:"noteId" format:"uuid"`
}

type createInput struct {
	Body struct {
		ClientID *uuid.UUID `json:"clientId,omitempty" format:"uuid" doc:"A UUIDv7 the client made for this note; uploading it again returns the stored note"`
		Title    string     `json:"title" minLength:"1" maxLength:"200"`
		Body     string     `json:"body,omitempty" maxLength:"20000"`
	}
}

type updateInput struct {
	NoteID string `path:"noteId" format:"uuid"`
	Body   struct {
		Version int32   `json:"version" minimum:"1" doc:"The version the change was made against; another one is 409"`
		Title   *string `json:"title,omitempty" minLength:"1" maxLength:"200"`
		Body    *string `json:"body,omitempty" maxLength:"20000"`
	}
}

type attachInput struct {
	NoteID string `path:"noteId" format:"uuid"`
	Body   struct {
		FileID  string `json:"fileId" format:"uuid" doc:"The id POST /files/note-attachment answered with"`
		Version int32  `json:"version" minimum:"1" doc:"The version the change was made against; another one is 409"`
	}
}

var errUnavailable = problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly")

type handlers struct {
	svc      *Service
	basePath string
}

func (h handlers) ready() error {
	if h.svc.db == nil {
		return errUnavailable
	}
	return nil
}

func (h handlers) list(ctx context.Context, in *listInput) (*httpx.List[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	f := Filter{Status: Status(in.Status), Query: in.Q}
	page, err := h.svc.List(ctx, f, paging.Request{Limit: in.Limit, Cursor: in.Cursor, Sort: in.Sort})
	if err != nil {
		return nil, err
	}
	p := principal(ctx)
	out := paging.Page[NoteResource]{Items: make([]NoteResource, len(page.Items)), Next: page.Next}
	for i, n := range page.Items {
		out.Items[i] = resource(n, p)
	}
	query := url.Values{"limit": {strconv.Itoa(in.Limit)}, "sort": {in.Sort}}
	if in.Status != "" {
		query.Set("status", in.Status)
	}
	if in.Q != "" {
		query.Set("q", in.Q)
	}
	return out.List(in.Limit, &url.URL{Path: h.basePath + "/notes", RawQuery: query.Encode()}), nil
}

func (h handlers) changes(ctx context.Context, in *changesInput) (*httpx.Feed[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	page, err := h.svc.Changes(ctx, in.Since, in.Limit)
	if err != nil {
		return nil, err
	}
	p := principal(ctx)
	out := paging.FeedPage[NoteResource]{Entries: make([]httpx.FeedEntry[NoteResource], len(page.Entries)), Next: page.Next, HasMore: page.HasMore}
	for i, e := range page.Entries {
		out.Entries[i] = httpx.FeedEntry[NoteResource]{Op: e.Op, ID: e.ID, Version: e.Version}
		if e.Record != nil {
			r := resource(*e.Record, p)
			out.Entries[i].Record = &r
		}
	}
	return &httpx.Feed[NoteResource]{Body: out.Body(in.Limit)}, nil
}

func (h handlers) get(ctx context.Context, in *idInput) (*httpx.One[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	id, err := ParseID(in.NoteID)
	if err != nil {
		return nil, ErrNotFound
	}
	n, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return httpx.OneOf(resource(n, principal(ctx))), nil
}

func (h handlers) create(ctx context.Context, in *createInput) (*httpx.Created[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	n, created, err := h.svc.Create(ctx, actingUser(ctx), Draft{ClientID: in.Body.ClientID, Title: in.Body.Title, Body: in.Body.Body})
	if err != nil {
		return nil, err
	}
	return httpx.CreatedOf(resource(n, principal(ctx)), created), nil
}

func (h handlers) update(ctx context.Context, in *updateInput) (*httpx.One[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	id, err := ParseID(in.NoteID)
	if err != nil {
		return nil, ErrNotFound
	}
	n, err := h.svc.Update(ctx, actingUser(ctx), id, in.Body.Version, Patch{Title: in.Body.Title, Body: in.Body.Body})
	if err != nil {
		return nil, err
	}
	return httpx.OneOf(resource(n, principal(ctx))), nil
}

func (h handlers) delete(ctx context.Context, in *idInput) (*httpx.NoContent, error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	id, err := ParseID(in.NoteID)
	if err != nil {
		return nil, ErrNotFound
	}
	if err := h.svc.Delete(ctx, id); err != nil {
		return nil, err
	}
	return &httpx.NoContent{}, nil
}

func (h handlers) archive(ctx context.Context, in *idInput) (*httpx.One[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	id, err := ParseID(in.NoteID)
	if err != nil {
		return nil, ErrNotFound
	}
	n, err := h.svc.Archive(ctx, actingUser(ctx), id)
	if err != nil {
		return nil, err
	}
	return httpx.OneOf(resource(n, principal(ctx))), nil
}

func (h handlers) attach(ctx context.Context, in *attachInput) (*httpx.One[NoteResource], error) {
	if err := h.ready(); err != nil {
		return nil, err
	}
	id, err := ParseID(in.NoteID)
	if err != nil {
		return nil, ErrNotFound
	}
	fileID, err := files.ParseID(in.Body.FileID)
	if err != nil {
		return nil, files.ErrNotFound
	}
	p := principal(ctx)
	uploader := files.Uploader{Kind: string(p.Kind()), ID: p.Subject()}
	n, err := h.svc.Attach(ctx, actingUser(ctx), uploader, id, in.Body.Version, fileID)
	if err != nil {
		return nil, err
	}
	return httpx.OneOf(resource(n, p)), nil
}

// principal is the caller; the operation's Need has already required one.
func principal(ctx context.Context) rbac.Principal {
	p, _ := auth.PrincipalFrom(ctx)
	return p
}

// actingUser is the person behind the request: the signed-in user, or the user a key or device acts for.
func actingUser(ctx context.Context) *users.ID {
	if id, ok := principal(ctx).ActingUser(); ok {
		return &id
	}
	return nil
}

func resource(n Note, p rbac.Principal) NoteResource {
	active := n.Status == StatusActive
	return NoteResource{
		ID: n.ID, ClientID: n.ClientID, Title: n.Title, Body: n.Body, Status: n.Status, ArchivedAt: n.ArchivedAt,
		WordCount: n.WordCount, Attachment: n.Attachment, Version: n.Version, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt,
		CreatedBy: n.CreatedBy,
		Can:       NoteCan{Edit: active && p.Can(PermWrite), Archive: active && p.Can(PermArchive), Delete: p.Can(PermWrite)},
	}
}

func mapError(err error) (*problem.Problem, bool) {
	var invalid *InvalidError
	switch {
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, "note not found"), true
	case errors.Is(err, ErrArchived):
		return problem.New(http.StatusConflict, "note_archived", "the note is archived and can no longer be changed"), true
	case errors.Is(err, ErrAlreadyArchived):
		return problem.New(http.StatusConflict, "illegal_transition", "the note is already archived"), true
	case errors.Is(err, ErrFilesOff):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, "files are not configured"), true
	case errors.Is(err, ErrExportTooLarge):
		return problem.New(http.StatusUnprocessableEntity, "export_too_large", "more than 10000 notes match; narrow the filter"), true
	case errors.As(err, &invalid):
		p := problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, invalid.Error())
		for _, f := range invalid.Fields {
			p.Errors = append(p.Errors, problem.FieldError{Location: "body." + f.Field, Code: f.Code, Message: f.Message})
		}
		return p, true
	}
	return nil, false
}
