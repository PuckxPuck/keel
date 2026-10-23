//go:build !nofiles

package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/fileshttp"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// FilesConfig is APP_FILES_*.
type FilesConfig = files.Config

// filesWiring holds what Build opens when APP_FILES_DRIVER names storage: the service requests use and
// the one the sweep uses.
type filesWiring struct {
	files   *files.Service
	sweeper *files.Service
	signer  *files.URLSigner
}

// downloadTimeout and uploadTimeout are how long one file may take to send or receive, beyond the
// server's write and read timeouts.
const (
	downloadTimeout = 10 * time.Minute
	uploadTimeout   = 10 * time.Minute
)

const kindFilesSweep = "files.sweep"

// openFiles opens the storage APP_FILES_* names, with the service requests use (the request's tenant)
// and the one the sweep uses (every tenant under the key prefix). Without a driver files stay off.
func (w *wiring) openFiles(ctx context.Context, cfg Config, deps Deps) error {
	if !cfg.Files.Enabled() {
		return nil
	}
	storage, err := files.Open(ctx, cfg.Files)
	if err != nil {
		return err
	}
	base := cfg.App.PublicURL
	if base == "" {
		base = "http://" + cfg.HTTP.Addr
	}
	if w.signer, err = files.NewURLSigner(base+BasePath+publicFilesPath, cfg.SigningKeys()...); err != nil {
		return err
	}
	opts := files.Options{
		Storage: storage, Inspector: cfg.Files.Inspector(), Policies: storagePolicies(), TempDir: cfg.Files.TempDir,
		KeyPrefix: cfg.Files.KeyPrefix, Signer: w.signer, Tx: files.TxRunner(appTx(deps.DB)),
	}
	if w.files, err = files.NewService(opts); err != nil {
		return err
	}
	opts.Tx = files.TxRunner(maintenanceTx(deps))
	w.sweeper, err = files.NewService(opts)
	return err
}

// filesMaintenance schedules the nightly sweep of expired uploads and orphaned objects.
func (w *wiring) filesMaintenance() {
	if w.sweeper == nil {
		return
	}
	w.queue.Handle(kindFilesSweep, func(ctx context.Context, _ jobs.Job) error {
		res, err := w.sweeper.Sweep(ctx, files.SweepOptions{})
		logx.From(ctx).Info("files swept", "expired", res.Expired, "orphans", res.Orphans)
		return err
	}, jobs.Global(), jobs.Lane(slowLane(w.cfg.Jobs)), jobs.Timeout(time.Hour))
	w.queue.Schedule(kindFilesSweep, kindFilesSweep, "47 2 * * *", time.UTC)
}

func filesMapper(err error) (*problem.Problem, bool) { return files.Mapper(err) }

func filesParts(cfg Config) []string {
	if cfg.Files.Enabled() {
		return []string{"files:" + string(cfg.Files.Driver)}
	}
	return nil
}

// filesChecks writes, reads and removes a probe object outside the keys files use.
func filesChecks(ctx context.Context, cfg Config) []Check {
	return []Check{checkFiles(ctx, cfg.Files)}
}

func checkFiles(ctx context.Context, cfg files.Config) Check {
	if !cfg.Enabled() {
		return pass("files", "off (APP_FILES_DRIVER is empty)")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	storage, err := files.Open(ctx, cfg)
	if err != nil {
		return fail("files", err.Error())
	}
	if c, ok := storage.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	key := cfg.KeyPrefix + "doctor/" + ids.New().String()
	body := []byte("keel doctor probe")
	err = storage.Put(ctx, key, files.PutInput{Body: bytes.NewReader(body), Size: int64(len(body)), SHA256: sha256.Sum256(body), ContentType: "text/plain"})
	if err != nil {
		return fail("files", "write: "+err.Error())
	}
	removed := false
	defer func() {
		if !removed {
			_ = storage.Delete(context.WithoutCancel(ctx), key)
		}
	}()
	r, _, err := storage.Get(ctx, key)
	if err != nil {
		return fail("files", "read: "+err.Error())
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, body) {
		return fail("files", "read back a different object")
	}
	if err := storage.Delete(ctx, key); err != nil {
		return fail("files", "remove: "+err.Error())
	}
	removed = true
	return pass("files", string(cfg.Driver)+" storage writable and readable")
}

// filePolicy is one upload kind: what it accepts, and the permission an upload of it needs.
type filePolicy struct {
	files.Policy
	Need rbac.Code
}

// filePolicies are the upload kinds POST /files/{kind} takes.
var filePolicies = map[string]filePolicy{}

func storagePolicies() map[string]files.Policy {
	out := make(map[string]files.Policy, len(filePolicies))
	for kind, p := range filePolicies {
		out[kind] = p.Policy
	}
	return out
}

// checkUploadNeeds refuses an upload kind whose permission the tenant catalogue lacks.
func checkUploadNeeds(cat *rbac.Catalogue) error {
	var errs []error
	for kind, p := range filePolicies {
		if !cat.Has(p.Need) {
			errs = append(errs, fmt.Errorf("upload kind %s needs %q, which is missing from the catalogue", kind, p.Need))
		}
	}
	return errors.Join(errs...)
}

// FileReader decides whether p may download f, a file attached to an owner of the type it is registered
// for, in the request's transaction.
type FileReader func(ctx context.Context, tx db.Transaction, p rbac.Principal, f files.File) (bool, error)

// fileReaders are the owner types whose files others may download; without one only the uploader may.
// A module that attaches files registers the check for its owner type here.
var fileReaders = map[string]FileReader{}

const publicFilesPath = "/public-files"

var tagFiles = []string{"files"}

type fileIDInput struct {
	FileID string `path:"fileId" format:"uuid"`
}

type uploadInput struct {
	Kind string `path:"kind" maxLength:"64"`
}

// fileBody is a download: the file's bytes with its own type, served by fileshttp.
type fileBody struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

var (
	errFilesOff        = problem.New(http.StatusNotFound, problem.CodeNotFound, "files are not configured")
	errNoUploadKind    = problem.New(http.StatusNotFound, problem.CodeNotFound, "no such upload kind")
	errUploadForbidden = problem.New(http.StatusForbidden, problem.CodeForbidden, "you do not have permission to upload this kind of file")
)

// registerFiles mounts uploads and downloads as operations, so the realm's whole middleware chain
// (session, tenant guard, rate limits, Need) runs before fileshttp streams the body.
func (w *wiring) registerFiles(api huma.API) {
	read, write := ratelimit.Class(ratelimit.ClassAPIRead), ratelimit.Class(ratelimit.ClassAPIWrite)
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: tagFiles}
	}
	download := func(id, path, summary string) huma.Operation {
		o := op(id, http.MethodGet, path, summary)
		o.Responses = map[string]*huma.Response{"200": {Description: "The file, as an attachment", Content: map[string]*huma.MediaType{
			"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}},
		}}}
		return o
	}
	httpx.Register(api, download("downloadFile", "/files/{"+fileshttp.IDParam+"}", "Download a file you may read"),
		noHandler[fileIDInput, fileBody], rbac.SignedIn(), read, httpx.Serve(w.filesHandler(w.privateFiles)))
	httpx.Register(api, download("downloadPublicFile", publicFilesPath+"/{"+fileshttp.IDParam+"}", "Download a public file by its signed link"),
		noHandler[fileIDInput, fileBody], rbac.Public(), read, httpx.Serve(w.filesHandler(w.publicFiles)))
	if len(filePolicies) == 0 {
		return
	}
	upload := op("uploadFile", http.MethodPost, "/files/{kind}", "Upload a file as the request body or one multipart part; stage it with the resource it belongs to")
	upload.DefaultStatus = http.StatusCreated
	upload.RequestBody = &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{
		"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}},
		"multipart/form-data":      {Schema: &huma.Schema{Type: "object", Properties: map[string]*huma.Schema{"file": {Type: "string", Format: "binary"}}}},
	}}
	httpx.Register(api, upload, noHandler[uploadInput, httpx.One[files.Receipt]], rbac.SignedIn(), write, httpx.Serve(w.filesHandler(w.uploadFiles)))
}

// noHandler is never called: httpx.Serve answers first.
func noHandler[I, O any](context.Context, *I) (*O, error) {
	return nil, errors.New("served by its http.Handler")
}

// filesHandler builds the fileshttp handler for each request, since the files service exists only once
// Build has opened storage.
func (w *wiring) filesHandler(pick func() http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.files == nil {
			problem.Write(rw, r, errFilesOff)
			return
		}
		pick().ServeHTTP(rw, r)
	})
}

func (w *wiring) fileOptions() fileshttp.Options {
	return fileshttp.Options{Files: w.files, Signer: w.signer, WriteTimeout: downloadTimeout, UploadTimeout: uploadTimeout, Authorize: w.authorizeFile, Load: w.loadFile, Admit: w.admitLink, Uploader: uploader}
}

func (w *wiring) privateFiles() http.Handler { return fileshttp.Private(w.fileOptions()) }

func (w *wiring) publicFiles() http.Handler { return fileshttp.Public(w.fileOptions()) }

func (w *wiring) uploadFiles() http.Handler {
	opts := w.fileOptions()
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		kind := r.PathValue("kind")
		policy, ok := filePolicies[kind]
		if !ok {
			problem.Write(rw, r, errNoUploadKind)
			return
		}
		if p, signedIn := auth.PrincipalFrom(r.Context()); !signedIn || !p.Can(policy.Need) {
			problem.Write(rw, r, errUploadForbidden)
			return
		}
		fileshttp.Upload(opts, kind).ServeHTTP(rw, r)
	})
}

func uploader(ctx context.Context) (files.Uploader, error) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return files.Uploader{}, auth.ErrNoSession
	}
	return files.Uploader{Kind: string(p.Kind()), ID: p.Subject()}, nil
}

// admitLink lets a public link serve only where the tenancy part says it may; a refused one reads as a
// missing file.
func (w *wiring) admitLink(ctx context.Context, tenant uuid.UUID) error {
	if ok, err := w.linkTenant(ctx, tenant); err != nil || !ok {
		return cmp.Or(err, files.ErrNotFound)
	}
	return nil
}

func (w *wiring) loadFile(ctx context.Context, id files.ID) (files.File, error) {
	var f files.File
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		f, err = w.files.File(ctx, tx, id)
		return err
	}, db.ReadOnly())
	return f, err
}

// authorizeFile lets the uploader read their file, and others when its owner type's reader agrees; any
// other file does not exist for the caller.
func (w *wiring) authorizeFile(ctx context.Context, id files.ID) (files.File, error) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return files.File{}, files.ErrNotFound
	}
	var f files.File
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		if f, err = w.files.File(ctx, tx, id); err != nil {
			return err
		}
		if f.Uploader.Kind == string(p.Kind()) && f.Uploader.ID == p.Subject() {
			return nil
		}
		read, ok := fileReaders[ownerType(f)]
		if !ok {
			return files.ErrNotFound
		}
		allowed, err := read(ctx, tx, p, f)
		if err == nil && !allowed {
			err = files.ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return f, err
}

func ownerType(f files.File) string {
	if f.Owner == nil {
		return ""
	}
	return f.Owner.Type
}
