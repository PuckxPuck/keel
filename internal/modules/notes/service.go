package notes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type noteTag struct{}

type ID = ids.ID[noteTag]

func ParseID(s string) (ID, error) { return ids.Parse[noteTag](s) }

type Note struct {
	ID ID `json:"id"`
	// ClientID is the id an offline client gave the note when it made it; a second upload with it
	// returns this note instead of making another.
	ClientID   *uuid.UUID  `json:"clientId,omitempty"`
	Title      string      `json:"title"`
	Body       string      `json:"body"`
	Status     Status      `json:"status"`
	ArchivedAt *time.Time  `json:"archivedAt,omitempty"`
	ArchivedBy *users.ID   `json:"archivedBy,omitempty"`
	WordCount  *int        `json:"wordCount,omitempty"`
	Attachment *Attachment `json:"attachment,omitempty"`
	Version    int32       `json:"version"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	CreatedBy  *users.ID   `json:"createdBy,omitempty"`
	UpdatedBy  *users.ID   `json:"updatedBy,omitempty"`
}

// Attachment is the file a note holds, as kit/files stored it.
type Attachment struct {
	FileID files.ID `json:"fileId"`
	Name   string   `json:"name"`
	Mime   string   `json:"mime"`
	Size   int64    `json:"size"`
}

// Draft is a new note.
type Draft struct {
	ClientID *uuid.UUID
	Title    string
	Body     string
}

// Patch is the fields an update sets; nil leaves a field as it is.
type Patch struct {
	Title *string
	Body  *string
}

// Filter narrows a list or an export; it is part of every cursor, so a cursor only continues the list it came from.
type Filter struct {
	Status Status `json:"status,omitempty"`
	Query  string `json:"q,omitempty"`
}

var (
	ErrNotFound       = errors.New("note not found")
	ErrFilesOff       = errors.New("files are not configured")
	ErrExportTooLarge = errors.New("too many notes to export at once")
)

const (
	entity = "note"
	// feedEntity names notes in tombstones.
	feedEntity = "notes"
	// OwnerType is how kit/files records a file attached to a note.
	OwnerType = "notes"
	// AttachmentKind is the upload kind (POST /files/note-attachment) a note's attachment is sent as.
	AttachmentKind = "note-attachment"
	archivedMail   = "note_archived"
	maxExportRows  = 10000
	exportPageSize = 500
)

type Service struct {
	db      *db.DB
	audit   *audit.Recorder
	cursors *paging.Keyset
	feed    *paging.Feed
	queue   *jobs.Queue
	mail    *mail.Service
	files   *files.Service
}

// NewService builds the service from the module's Deps; without a database (route:list) it has no feed.
func NewService(d Deps) (*Service, error) {
	s := &Service{db: d.DB, audit: d.Audit, cursors: d.Cursors, queue: d.Jobs, mail: d.Mail, files: d.Files}
	if d.Cursors == nil {
		return s, nil
	}
	feed, err := paging.NewFeed(d.Cursors, paging.FeedOptions{Entity: feedEntity, Retention: d.FeedRetention})
	if err != nil {
		return nil, fmt.Errorf("notes: change feed: %w", err)
	}
	s.feed = feed
	return s, nil
}

// now is the business clock at the database's precision, so what a write returns equals what a read finds.
func now(ctx context.Context) time.Time {
	return clock.Business(ctx).Now().UTC().Truncate(time.Microsecond)
}

// Create stores a new note and queues its index job. A draft whose ClientID is already stored returns
// that note with created false.
func (s *Service) Create(ctx context.Context, by *users.ID, d Draft) (note Note, created bool, err error) {
	title, titleErr := cleanTitle(d.Title)
	if err := invalid(titleErr, checkBody(d.Body)); err != nil {
		return Note{}, false, err
	}
	at := now(ctx)
	n := Note{
		ID: ids.NewOf[noteTag](), ClientID: d.ClientID, Title: title, Body: d.Body, Status: StatusActive,
		Version: 1, CreatedAt: at, UpdatedAt: at, CreatedBy: by, UpdatedBy: by,
	}
	err = db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		created = false
		if d.ClientID != nil {
			stored, err := byClientID(ctx, tx, *d.ClientID)
			if err == nil {
				note = stored
				return nil
			}
			if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if err := insert(ctx, tx, n); err != nil {
			return err
		}
		if err := s.enqueueIndex(ctx, tx, n); err != nil {
			return err
		}
		note, created = n, true
		return s.audit.Record(ctx, tx, audit.Event{Action: entity + ".created", Entity: entity, EntityID: n.ID.String(), After: n})
	})
	if d.ClientID != nil && db.IsUniqueViolation(err) {
		// Another upload with this ClientID committed first; answer with the note it stored.
		note, err = s.byClientID(ctx, *d.ClientID)
	}
	if err != nil {
		return Note{}, false, err
	}
	return note, created, nil
}

func (s *Service) byClientID(ctx context.Context, clientID uuid.UUID) (Note, error) {
	var out Note
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		out, err = byClientID(ctx, tx, clientID)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) Get(ctx context.Context, id ID) (Note, error) {
	var out Note
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		out, err = get(ctx, tx, id, false)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) List(ctx context.Context, f Filter, p paging.Request) (paging.Page[Note], error) {
	var page paging.Page[Note]
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		page, err = list(ctx, tx, s.cursors, f, p)
		return err
	}, db.ReadOnly())
	return page, err
}

// Changes is the page of changes after since (empty for a full sync), deletes included.
func (s *Service) Changes(ctx context.Context, since string, limit int) (paging.FeedPage[Note], error) {
	var page paging.FeedPage[Note]
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		page, err = changes(ctx, tx, s.feed, since, limit)
		return err
	}, db.ReadOnly())
	return page, err
}

// Update applies patch if the note is still at version; otherwise it returns an *occ.StaleError. The
// update itself is conditional on the version, so no lock is needed. A patch that changes nothing
// writes nothing.
func (s *Service) Update(ctx context.Context, by *users.ID, id ID, version int32, patch Patch) (Note, error) {
	var title string
	var titleErr, bodyErr *FieldError
	if patch.Title != nil {
		title, titleErr = cleanTitle(*patch.Title)
	}
	if patch.Body != nil {
		bodyErr = checkBody(*patch.Body)
	}
	if err := invalid(titleErr, bodyErr); err != nil {
		return Note{}, err
	}
	var after Note
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		before, err := get(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if _, err := transition(before.Status, ActionEdit); err != nil {
			return err
		}
		after = before
		if patch.Title != nil {
			after.Title = title
		}
		if patch.Body != nil {
			after.Body = *patch.Body
		}
		if after.Title == before.Title && after.Body == before.Body {
			if before.Version != version {
				return &occ.StaleError{Current: current(before)}
			}
			return nil
		}
		after.Version, after.UpdatedAt, after.UpdatedBy = version+1, now(ctx), by
		if err := update(ctx, tx, after, version); err != nil {
			return err
		}
		if after.Body != before.Body {
			if err := s.enqueueIndex(ctx, tx, after); err != nil {
				return err
			}
		}
		return s.audit.Record(ctx, tx, audit.Event{Action: entity + ".updated", Entity: entity, EntityID: id.String(), Before: before, After: after})
	})
	if err != nil {
		return Note{}, err
	}
	return after, nil
}

// Archive makes a note read-only and mails its author.
func (s *Service) Archive(ctx context.Context, by *users.ID, id ID) (Note, error) {
	var after Note
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		before, err := get(ctx, tx, id, true)
		if err != nil {
			return err
		}
		next, err := transition(before.Status, ActionArchive)
		if err != nil {
			return err
		}
		at := now(ctx)
		after = before
		after.Status, after.ArchivedAt, after.ArchivedBy = next, &at, by
		after.Version, after.UpdatedAt, after.UpdatedBy = before.Version+1, at, by
		if err := update(ctx, tx, after, before.Version); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, audit.Event{Action: entity + ".archived", Entity: entity, EntityID: id.String(), Before: before, After: after}); err != nil {
			return err
		}
		return s.mailAuthor(ctx, tx, after)
	})
	if err != nil {
		return Note{}, err
	}
	return after, nil
}

// mailAuthor tells the note's author, while they have an active account, that it was archived.
func (s *Service) mailAuthor(ctx context.Context, tx db.Tx[db.Tenant], n Note) error {
	if s.mail == nil || n.CreatedBy == nil {
		return nil
	}
	author, err := users.Get(ctx, tx, *n.CreatedBy)
	if errors.Is(err, users.ErrNotFound) || (err == nil && author.Status != users.Active) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.mail.Enqueue(ctx, tx, mail.Email{
		To: []string{author.Email}, Template: archivedMail, Data: struct{ Name, Title string }{Name: author.Name, Title: n.Title},
	})
	return err
}

// Attach makes the uploaded file the note's attachment, replacing (and removing) the one it had.
func (s *Service) Attach(ctx context.Context, by *users.ID, uploader files.Uploader, id ID, version int32, fileID files.ID) (Note, error) {
	if s.files == nil {
		return Note{}, ErrFilesOff
	}
	var after Note
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		before, err := get(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if _, err := transition(before.Status, ActionAttach); err != nil {
			return err
		}
		if before.Version != version {
			return &occ.StaleError{Current: current(before)}
		}
		f, err := s.files.Stage(ctx, tx, fileID, uploader)
		if err != nil {
			return err
		}
		if err := s.files.Attach(ctx, tx, f.ID, AttachmentKind, files.Owner{Type: OwnerType, ID: id.UUID()}, uploader); err != nil {
			return err
		}
		after = before
		after.Attachment = &Attachment{FileID: f.ID, Name: f.Name, Mime: f.Mime, Size: f.Size}
		after.Version, after.UpdatedAt, after.UpdatedBy = version+1, now(ctx), by
		if err := update(ctx, tx, after, version); err != nil {
			return err
		}
		if before.Attachment != nil {
			if err := s.removeFile(ctx, tx, before.Attachment.FileID); err != nil {
				return err
			}
		}
		return s.audit.Record(ctx, tx, audit.Event{Action: entity + ".attached", Entity: entity, EntityID: id.String(), Before: before, After: after})
	})
	if err != nil {
		return Note{}, err
	}
	return after, nil
}

// Delete removes the note and its attachment, and leaves a tombstone so the change feed delivers the delete.
func (s *Service) Delete(ctx context.Context, id ID) error {
	return db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		before, err := get(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := transition(before.Status, ActionDelete); err != nil {
			return err
		}
		if err := remove(ctx, tx, id); err != nil {
			return err
		}
		if err := paging.Tombstone(ctx, tx, feedEntity, id.UUID()); err != nil {
			return err
		}
		if before.Attachment != nil {
			if err := s.removeFile(ctx, tx, before.Attachment.FileID); err != nil {
				return err
			}
		}
		return s.audit.Record(ctx, tx, audit.Event{Action: entity + ".deleted", Entity: entity, EntityID: id.String(), Before: before})
	})
}

// removeFile deletes an attachment's row now and its object once tx commits. With files turned off
// since, the object stays where it is.
func (s *Service) removeFile(ctx context.Context, tx db.Tx[db.Tenant], id files.ID) error {
	if s.files == nil {
		return nil
	}
	if err := s.files.Remove(ctx, tx, id); err != nil && !errors.Is(err, files.ErrNotFound) {
		return err
	}
	return nil
}

// Export calls write for every note f selects, in sort order. It walks the list a page at a time, each in
// its own short transaction, and refuses more than maxExportRows notes.
func (s *Service) Export(ctx context.Context, f Filter, sort string, write func(Note) error) error {
	req := paging.Request{Limit: exportPageSize, Sort: sort}
	written := 0
	for {
		page, err := s.List(ctx, f, req)
		if err != nil {
			return err
		}
		for _, n := range page.Items {
			if written == maxExportRows {
				return ErrExportTooLarge
			}
			if err := write(n); err != nil {
				return err
			}
			written++
		}
		if page.Next == "" {
			return nil
		}
		req.Cursor = page.Next
	}
}

func (s *Service) enqueueIndex(ctx context.Context, tx db.Tx[db.Tenant], n Note) error {
	_, err := s.queue.Enqueue(ctx, tx, KindIndex, IndexPayload{NoteID: n.ID})
	return err
}

// index stores the word count of the note's body as it is now; the row lock makes the last job to run
// count the latest body. Running it again stores the same.
func (s *Service) index(ctx context.Context, id ID) error {
	return db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		n, err := get(ctx, tx, id, true)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return setWordCount(ctx, tx, id, wordCount(n.Body))
	})
}

// ReadAttachment is the files reader for notes: p may download a note's attachment when it may read
// notes and the note still holds that file.
func ReadAttachment(ctx context.Context, tx db.Transaction, p rbac.Principal, f files.File) (bool, error) {
	if !p.Can(PermRead) || f.Owner == nil || f.Kind != AttachmentKind {
		return false, nil
	}
	// Notes are read in tenant transactions only; a request without a tenant has no notes.
	in, ok := tx.(db.Tx[db.Tenant])
	if !ok {
		return false, nil
	}
	n, err := get(ctx, in, ids.FromUUID[noteTag](f.Owner.ID), false)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n.Attachment != nil && n.Attachment.FileID == f.ID, nil
}
