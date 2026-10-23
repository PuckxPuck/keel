package files

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

type Options struct {
	Storage   Storage
	Inspector *inspect.Inspector
	// Scanner is the optional antivirus hook, run on the content that is kept.
	Scanner inspect.Scanner
	// Policies by upload kind.
	Policies map[string]Policy
	// TempDir holds uploads while they are checked; empty means the system temporary directory.
	TempDir string
	// KeyPrefix namespaces this app and environment in a shared bucket (Config.KeyPrefix).
	KeyPrefix string
	// Signer makes public links that fileshttp.Public serves.
	Signer *URLSigner
	// Tx runs Put's and Sweep's own short transactions; under tenancy one that sees every row under KeyPrefix.
	Tx TxRunner
}

// TxRunner opens a transaction of the caller's scope: plain, or under tenancy a tenant or operator one.
type TxRunner func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error

// PlainTx runs the service's transactions as plain transactions on d.
func PlainTx(d *db.DB) TxRunner {
	return func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
		return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) })
	}
}

type Service struct {
	opts Options
}

func NewService(opts Options) (*Service, error) {
	if opts.Storage == nil || opts.Inspector == nil || opts.Tx == nil {
		return nil, errors.New("files: a service needs storage, an inspector and a transaction runner")
	}
	if !validPrefix(opts.KeyPrefix) {
		return nil, errors.New("files: key prefix must be empty or key segments ending in a slash")
	}
	_, presigns := opts.Storage.(Presigner)
	for kind, p := range opts.Policies {
		if err := p.validate(kind); err != nil {
			return nil, err
		}
		if p.Presign && !presigns {
			return nil, fmt.Errorf("files: policy %s presigns but the storage cannot", kind)
		}
	}
	return &Service{opts: opts}, nil
}

func (s *Service) Storage() Storage { return s.opts.Storage }

// Policy is the policy of an upload kind.
func (s *Service) Policy(kind string) (Policy, bool) {
	p, ok := s.opts.Policies[kind]
	return p, ok
}

// Upload is a file a client sent, read once from Body.
type Upload struct {
	Kind string
	Name string
	Body io.Reader
	By   Uploader
}

// Put streams the upload to a temporary file under the kind's size cap, hashing it on the way, detects
// its type from the content and inspects it. It then records a pending row in its own transaction and
// only then writes the object, so every object this package writes has a row first. The caller claims
// the file with Stage; Sweep removes it if nobody does.
func (s *Service) Put(ctx context.Context, up Upload) (Receipt, error) {
	if err := up.By.validate(); err != nil {
		return Receipt{}, err
	}
	policy, ok := s.opts.Policies[up.Kind]
	if !ok {
		return Receipt{}, ErrUnknownKind
	}
	spool, size, sum, err := s.spool(up.Body, policy.MaxBytes)
	if err != nil {
		return Receipt{}, err
	}
	defer s.discard(ctx, spool)

	mime, err := s.opts.Inspector.Detect(ctx, spool, size)
	if err != nil {
		return Receipt{}, refusal(err)
	}
	if !slices.Contains(policy.Types, mime) {
		return Receipt{}, ErrTypeNotAllowed
	}
	content := spool
	if policy.Inspect {
		if content, size, sum, err = s.inspect(ctx, spool, size, sum, mime, policy.MaxBytes); err != nil {
			return Receipt{}, err
		}
		if content != spool {
			defer s.discard(ctx, content)
		}
	}
	if s.opts.Scanner != nil {
		if err := s.opts.Scanner.Scan(ctx, io.NewSectionReader(content, 0, size), size); err != nil {
			return Receipt{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return Receipt{}, err
	}
	now := clock.Wall(ctx).Now().UTC()
	f := File{
		ID: ids.NewOf[fileTag](), Kind: up.Kind, State: Pending, Uploader: up.By, Name: cleanName(up.Name), Mime: mime,
		Size: size, SHA256: sum[:], Key: newKey(ctx, s.opts.KeyPrefix), Visibility: policy.Visibility, CreatedAt: now,
	}
	if err := s.opts.Tx(ctx, func(ctx context.Context, tx db.Transaction) error { return insertFile(ctx, tx, f) }); err != nil {
		return Receipt{}, err
	}
	if err := s.opts.Storage.Put(ctx, f.Key, PutInput{Body: content, Size: size, SHA256: sum, ContentType: mime}); err != nil {
		s.forget(ctx, f.ID)
		return Receipt{}, err
	}
	return Receipt{ID: f.ID, Kind: f.Kind, Name: f.Name, Mime: f.Mime, Size: f.Size}, nil
}

// forget drops the pending row of an upload whose object was not written; a failure leaves it to Sweep.
func (s *Service) forget(ctx context.Context, id ID) {
	err := s.opts.Tx(ctx, func(ctx context.Context, tx db.Transaction) error { return deletePending(ctx, tx, id) })
	if err != nil {
		logx.From(ctx).Warn("files: drop pending upload", slog.String("file_id", id.String()), slog.Any("error", err))
	}
}

func (s *Service) spool(body io.Reader, maxBytes int64) (*os.File, int64, [sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.CreateTemp(s.opts.TempDir, "upload-*")
	if err != nil {
		return nil, 0, sum, fmt.Errorf("files: spool: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, maxBytes+1))
	switch {
	case err != nil:
		err = fmt.Errorf("files: read upload: %w", err)
	case n > maxBytes:
		err = ErrTooLarge
	case n == 0:
		err = ErrEmpty
	}
	if err != nil {
		_ = f.Close()           // the read error is the one to report
		_ = os.Remove(f.Name()) // a leftover spool file is only disk space
		return nil, 0, sum, err
	}
	return f, n, [sha256.Size]byte(h.Sum(nil)), nil
}

func (s *Service) inspect(ctx context.Context, spool *os.File, size int64, sum [sha256.Size]byte, mime string, maxBytes int64) (*os.File, int64, [sha256.Size]byte, error) {
	out, err := os.CreateTemp(s.opts.TempDir, "inspect-*")
	if err != nil {
		return nil, 0, sum, fmt.Errorf("files: spool: %w", err)
	}
	h := sha256.New()
	cw := &cappedWriter{w: io.MultiWriter(out, h), left: maxBytes}
	rewritten, err := s.opts.Inspector.Inspect(ctx, spool, size, mime, cw)
	if err != nil || !rewritten {
		s.discard(ctx, out)
		return spool, size, sum, refusal(err)
	}
	return out, maxBytes - cw.left, [sha256.Size]byte(h.Sum(nil)), nil
}

// cappedWriter refuses a rewrite that grows past the policy's cap.
type cappedWriter struct {
	w    io.Writer
	left int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		return 0, ErrTooLarge
	}
	n, err := c.w.Write(p)
	c.left -= int64(n)
	return n, err
}

func refusal(err error) error {
	if err == nil || errors.Is(err, ErrTooLarge) {
		return err
	}
	for _, e := range []error{inspect.ErrMalformed, inspect.ErrBudget, inspect.ErrActiveContent, inspect.ErrImageTooLarge, inspect.ErrNotText} {
		if errors.Is(err, e) {
			return fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	if errors.Is(err, inspect.ErrUnsupported) {
		return fmt.Errorf("%w: %w", ErrTypeNotAllowed, err)
	}
	return err
}

func (s *Service) discard(ctx context.Context, f *os.File) {
	_ = f.Close() // only read from
	if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		logx.From(ctx).Warn("files: remove temporary upload", slog.Any("error", err))
	}
}

// Stage claims a pending upload in the caller's transaction. Only its uploader can; any other caller,
// an unknown id or a file already staged gets ErrNotFound.
func (s *Service) Stage(ctx context.Context, tx db.Transaction, id ID, by Uploader) (File, error) {
	if err := by.validate(); err != nil {
		return File{}, err
	}
	ok, err := stageFile(ctx, tx, id, by, clock.Wall(ctx).Now().UTC())
	if err != nil {
		return File{}, err
	}
	if !ok {
		return File{}, ErrNotFound
	}
	return loadFile(ctx, tx, id, false)
}

// Attach gives a staged file of the given kind its owner. by must be the uploader that staged it, or
// SystemUploader; a missing, attached, other-kind or other uploader's file is ErrNotFound.
func (s *Service) Attach(ctx context.Context, tx db.Transaction, id ID, kind string, owner Owner, by Uploader) error {
	if owner.Type == "" || len(owner.Type) > maxOwnerType || owner.ID == uuid.Nil {
		return fmt.Errorf("files: an owner needs a type of 1 to %d characters and an id", maxOwnerType)
	}
	if err := by.validate(); err != nil {
		return err
	}
	ok, err := attachFile(ctx, tx, id, kind, owner, by, clock.Wall(ctx).Now().UTC())
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

// File loads a file's row; the caller checks the reader's permission before serving it.
func (s *Service) File(ctx context.Context, tx db.Transaction, id ID) (File, error) {
	return loadFile(ctx, tx, id, false)
}

// Remove deletes the row in the caller's transaction and the object after it commits. A failed object
// delete leaves an orphan, which Sweep removes.
func (s *Service) Remove(ctx context.Context, tx db.Transaction, id ID) error {
	f, err := loadFile(ctx, tx, id, true)
	if err != nil {
		return err
	}
	if err := deleteFile(ctx, tx, id); err != nil {
		return err
	}
	return db.AfterCommit(ctx, func(ctx context.Context) {
		if err := s.opts.Storage.Delete(ctx, f.Key); err != nil {
			logx.From(ctx).Warn("files: delete object after commit", slog.String("file_id", f.ID.String()), slog.Any("error", err))
		}
	})
}

// Open reads a file's object; a key this package did not make under its prefix, or under tenancy for
// another tenant than the context's, is ErrNotFound.
func (s *Service) Open(ctx context.Context, f File) (io.ReadCloser, ObjectInfo, error) {
	if tenant, ok := keyTenant(s.opts.KeyPrefix, f.Key); !ok || tenant != tenantSegment(ctx) {
		return nil, ObjectInfo{}, ErrNotFound
	}
	return s.opts.Storage.Get(ctx, f.Key)
}

// PublicURL is an expiring link to a public file, signed for fileshttp.Public, or presigned by the
// storage when the file's policy opts in. Like Open, it treats a key of another tenant than the
// context's as ErrNotFound: a presigned link bypasses row-level security and fileshttp alike.
func (s *Service) PublicURL(ctx context.Context, f File, ttl time.Duration) (string, error) {
	if f.Visibility != Public {
		return "", ErrNotPublic
	}
	if tenant, ok := keyTenant(s.opts.KeyPrefix, f.Key); !ok || tenant != tenantSegment(ctx) {
		return "", ErrNotFound
	}
	if ttl <= 0 || ttl > MaxLinkTTL {
		return "", fmt.Errorf("files: link lifetime must be positive and at most %s", MaxLinkTTL)
	}
	if p, ok := s.opts.Storage.(Presigner); ok && s.opts.Policies[f.Kind].Presign {
		return p.PresignGet(ctx, f.Key, ttl, f.Name, f.Mime)
	}
	if s.opts.Signer == nil {
		return "", errors.New("files: no signer for public links")
	}
	tenant, _ := db.TenantOf(ctx)
	return s.opts.Signer.URL(f.ID, tenant, clock.Wall(ctx).Now(), ttl)
}
