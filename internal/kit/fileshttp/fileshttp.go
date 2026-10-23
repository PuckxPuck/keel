// Package fileshttp serves stored files as downloads (permission checked per file, always as an
// attachment, never sniffed or rendered as active content) and takes uploads as a stream.
package fileshttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

// Loader loads the file a request names. For private downloads it also checks that the caller may read
// it, and answers files.ErrNotFound when not, so a file the caller cannot see does not exist.
type Loader func(ctx context.Context, id files.ID) (files.File, error)

type Options struct {
	Files *files.Service
	// Authorize serves Private.
	Authorize Loader
	// Load, Signer and Admit serve Public; the signed link is the permission.
	Load   Loader
	Signer *files.URLSigner
	// Admit runs once a public link verifies, before its tenant (uuid.Nil without tenancy) becomes the
	// context's and Load runs. Under tenancy it refuses a link of another tenant than the host's, and of a
	// tenant that is suspended or gone, with files.ErrNotFound. Nil panics, so no wiring skips the check.
	Admit func(ctx context.Context, tenant uuid.UUID) error
	// Uploader names the caller of Upload, or answers an error (a problem such as 401) to refuse them.
	Uploader func(ctx context.Context) (files.Uploader, error)
	// WriteTimeout extends the server's write deadline for a download (0 keeps it).
	WriteTimeout time.Duration
	// UploadTimeout extends the server's read and write deadlines for an upload (0 keeps them), so a
	// large file on a slow link is not cut at the server's read timeout.
	UploadTimeout time.Duration
}

// IDParam is the path parameter that names the file: mount downloads at a path ending in {fileId}.
const IDParam = "fileId"

// Private answers GET with the file named by the IDParam path value, after Authorize.
func Private(opts Options) http.Handler {
	if opts.Files == nil || opts.Authorize == nil {
		panic("fileshttp: Private needs Files and Authorize")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		f, err := opts.Authorize(r.Context(), id)
		if err != nil {
			fail(w, r, err)
			return
		}
		serve(w, r, opts, f)
	})
}

// Public answers GET with a public file when the link's expires and sig parameters verify and Admit
// lets it serve here.
func Public(opts Options) http.Handler {
	if opts.Files == nil || opts.Load == nil || opts.Signer == nil || opts.Admit == nil {
		panic("fileshttp: Public needs Files, Load, Signer and Admit")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		tenant, err := opts.Signer.Verify(id, q.Get("tenant"), q.Get("expires"), q.Get("sig"), clock.Wall(r.Context()).Now())
		if err != nil {
			fail(w, r, err)
			return
		}
		ctx := r.Context()
		if err := opts.Admit(ctx, tenant); err != nil {
			fail(w, r, err)
			return
		}
		if tenant != uuid.Nil {
			ctx = db.WithTenant(ctx, tenant)
			r = r.WithContext(ctx)
		}
		f, err := opts.Load(ctx, id)
		if err == nil && f.Visibility != files.Public {
			err = files.ErrNotPublic
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		serve(w, r, opts, f)
	})
}

// multipartOverhead is what boundaries and part headers may add to a form around the file.
const multipartOverhead = 16 << 10

const CodeInvalidUpload = "invalid_upload"

var errInvalidUpload = problem.New(http.StatusBadRequest, CodeInvalidUpload, "send the file as the request body or as the one file part of a multipart form")

// Upload answers POST by streaming the file to Files.Put as kind and replying 201 with the receipt in the
// data envelope. The body is the file itself, named by a Content-Disposition filename, or a
// multipart/form-data form whose only part is the file. The kind's size cap applies before and during
// the read; nothing is buffered beyond the stream.
func Upload(opts Options, kind string) http.Handler {
	if opts.Files == nil || opts.Uploader == nil {
		panic("fileshttp: Upload needs Files and Uploader")
	}
	policy, ok := opts.Files.Policy(kind)
	if !ok {
		panic("fileshttp: Upload has no policy for kind " + kind)
	}
	limit := policy.MaxBytes + multipartOverhead
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		by, err := opts.Uploader(r.Context())
		if err != nil {
			fail(w, r, err)
			return
		}
		if r.ContentLength > limit {
			fail(w, r, files.ErrTooLarge)
			return
		}
		if opts.UploadTimeout > 0 {
			// not every ResponseWriter supports deadlines; the server's own timeouts then apply
			rc, until := http.NewResponseController(w), clock.Wall(r.Context()).Now().Add(opts.UploadTimeout)
			_ = rc.SetReadDeadline(until)
			_ = rc.SetWriteDeadline(until)
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		receipt, err := upload(r, opts.Files, kind, by)
		if err != nil {
			fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(httpx.OneBody[files.Receipt]{Data: receipt}) // a failed write means the client is gone
	})
}

func upload(r *http.Request, svc *files.Service, kind string, by files.Uploader) (files.Receipt, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Disposition")) // a missing name is "file"
		return svc.Put(r.Context(), files.Upload{Kind: kind, Name: params["filename"], Body: r.Body, By: by})
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return files.Receipt{}, errInvalidUpload
	}
	part, err := mr.NextPart()
	if err != nil || part.FileName() == "" {
		return files.Receipt{}, errInvalidUpload
	}
	receipt, err := svc.Put(r.Context(), files.Upload{Kind: kind, Name: part.FileName(), Body: part, By: by})
	if err != nil {
		return files.Receipt{}, err
	}
	// a stored upload nobody stages is removed by Sweep
	if _, err := mr.NextPart(); !errors.Is(err, io.EOF) {
		return files.Receipt{}, errInvalidUpload
	}
	return receipt, nil
}

func pathID(w http.ResponseWriter, r *http.Request) (files.ID, bool) {
	id, err := files.ParseID(r.PathValue(IDParam))
	if err != nil {
		fail(w, r, files.ErrNotFound)
		return files.ID{}, false
	}
	return id, true
}

func serve(w http.ResponseWriter, r *http.Request, opts Options, f files.File) {
	body, info, err := opts.Files.Open(r.Context(), f)
	if err != nil {
		fail(w, r, err)
		return
	}
	defer func() { _ = body.Close() }()
	if opts.WriteTimeout > 0 {
		// not every ResponseWriter supports deadlines; the server's own timeout then applies
		_ = http.NewResponseController(w).SetWriteDeadline(clock.Wall(r.Context()).Now().Add(opts.WriteTimeout))
	}
	h := w.Header()
	h.Set("Content-Type", f.Mime)
	h.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	h.Set("Content-Disposition", files.ContentDisposition(f.Name))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, body); err != nil {
		logx.From(r.Context()).Info("fileshttp: download cut short", slog.String("file_id", f.ID.String()), slog.Any("error", err))
	}
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		err = files.ErrTooLarge
	}
	if p, ok := files.Mapper(err); ok {
		problem.Write(w, r, p)
		return
	}
	var p *problem.Problem
	if errors.As(err, &p) {
		problem.Write(w, r, p)
		return
	}
	logx.From(r.Context()).Error("fileshttp: request", slog.Any("error", err))
	problem.Write(w, r, problem.Internal())
}
