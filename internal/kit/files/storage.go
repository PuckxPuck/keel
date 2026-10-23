package files

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

type ObjectInfo struct {
	Key     string
	Size    int64
	ModTime time.Time
}

// PutInput is a fully spooled object: its size and checksum are known before it is sent.
type PutInput struct {
	Body        io.ReadSeeker
	Size        int64
	SHA256      [sha256.Size]byte
	ContentType string
}

// Storage keeps objects by key. Delete of a missing object succeeds; List streams objects with the prefix.
type Storage interface {
	Put(ctx context.Context, key string, in PutInput) error
	Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error)
	Stat(ctx context.Context, key string) (ObjectInfo, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string, fn func(ObjectInfo) error) error
}

// Presigner is a storage that can hand out its own expiring download URLs (S3).
type Presigner interface {
	PresignGet(ctx context.Context, key string, ttl time.Duration, name, mime string) (string, error)
}

var errBadKey = errors.New("files: invalid storage key")

const maxKey = 512

// validKey accepts only the keys this package makes: segments of letters, digits, '.', '_' and '-',
// none starting with a dot, so no key names the temporary directory or a parent.
func validKey(key string) bool {
	if key == "" || len(key) > maxKey {
		return false
	}
	for seg := range strings.SplitSeq(key, "/") {
		if seg == "" || seg[0] == '.' {
			return false
		}
		for i := range len(seg) {
			if !keyChar(seg[i]) {
				return false
			}
		}
	}
	return true
}

func keyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

func validPrefix(p string) bool {
	return p == "" || len(p) <= maxKeyPrefix && strings.HasSuffix(p, "/") && validKey(strings.TrimSuffix(p, "/"))
}

// objectDir is the namespace of this package's keys under the configured prefix.
const objectDir = "f/"

const keyRandom = 32

// newKey is <prefix>f/<ab>/<cd>/<abcd...>, or <prefix>f/<tenant>/<ab>/<cd>/<abcd...> with a tenant in
// ctx: two shard levels from the random part keep directories small, and one listing of f/ covers every
// tenant.
func newKey(ctx context.Context, prefix string) string {
	b := make([]byte, keyRandom/2)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	r := hex.EncodeToString(b)
	key := prefix + objectDir
	if t := tenantSegment(ctx); t != "" {
		key += t + "/"
	}
	return key + r[:2] + "/" + r[2:4] + "/" + r
}

func tenantSegment(ctx context.Context) string {
	if id, ok := db.TenantOf(ctx); ok {
		return id.String()
	}
	return ""
}

// keyTenant reports whether key has a shape newKey gives under prefix, and the tenant segment in it.
func keyTenant(prefix, key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, prefix+objectDir)
	if !ok {
		return "", false
	}
	tenant := ""
	if len(rest) == tenantSegmentLen+1+6+keyRandom {
		id, err := uuid.Parse(rest[:tenantSegmentLen])
		if err != nil || rest[tenantSegmentLen] != '/' || id.String() != rest[:tenantSegmentLen] {
			return "", false
		}
		tenant, rest = rest[:tenantSegmentLen], rest[tenantSegmentLen+1:]
	}
	if len(rest) != 6+keyRandom || rest[2] != '/' || rest[5] != '/' {
		return "", false
	}
	r := rest[6:]
	if rest[:2] != r[:2] || rest[3:5] != r[2:4] {
		return "", false
	}
	for i := range len(r) {
		if (r[i] < '0' || r[i] > '9') && (r[i] < 'a' || r[i] > 'f') {
			return "", false
		}
	}
	return tenant, true
}

const tenantSegmentLen = 36

const localTemp = ".tmp"

// Local keeps objects under a directory. Every path goes through os.Root, so neither a crafted key nor a
// symlink planted in the directory can reach outside it.
type Local struct {
	root *os.Root
}

// NewLocal opens dir, which must exist.
func NewLocal(dir string) (*Local, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("files: open root: %w", err)
	}
	if err := root.MkdirAll(localTemp, 0o700); err != nil {
		_ = root.Close() // the mkdir error is the one to report
		return nil, fmt.Errorf("files: temp directory: %w", err)
	}
	return &Local{root: root}, nil
}

func (l *Local) Close() error { return l.root.Close() }

// Put writes to a temporary file, checks size and checksum, syncs it, renames it into place and syncs
// the directories, so a crash leaves either the whole object or none.
func (l *Local) Put(_ context.Context, key string, in PutInput) (err error) {
	if !validKey(key) {
		return errBadKey
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	tmp := localTemp + "/" + hex.EncodeToString(b)
	f, err := l.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("files: create: %w", err)
	}
	defer func() {
		if err != nil {
			_ = l.root.Remove(tmp) // best effort; the write error is the one to report
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(in.Body, in.Size+1))
	if err == nil && (n != in.Size || [sha256.Size]byte(h.Sum(nil)) != in.SHA256) {
		err = errors.New("files: object does not match its size or checksum")
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("files: write: %w", err)
	}
	dir := path.Dir(key)
	if err := l.root.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("files: mkdir: %w", err)
	}
	if err := l.root.Rename(tmp, key); err != nil {
		return fmt.Errorf("files: rename: %w", err)
	}
	if err := l.syncDir(localTemp); err != nil {
		return err
	}
	for {
		if err := l.syncDir(dir); err != nil || dir == "." {
			return err
		}
		dir = path.Dir(dir)
	}
}

func (l *Local) syncDir(dir string) error {
	d, err := l.root.Open(dir)
	if err != nil {
		return fmt.Errorf("files: sync dir: %w", err)
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("files: sync dir: %w", err)
	}
	return nil
}

func (l *Local) Get(_ context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	if !validKey(key) {
		return nil, ObjectInfo{}, errBadKey
	}
	f, err := l.root.Open(key)
	if err != nil {
		return nil, ObjectInfo{}, notFoundOr(err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close() // nothing was read
		return nil, ObjectInfo{}, errors.Join(err, ErrNotFound)
	}
	return f, ObjectInfo{Key: key, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

func (l *Local) Stat(_ context.Context, key string) (ObjectInfo, error) {
	if !validKey(key) {
		return ObjectInfo{}, errBadKey
	}
	fi, err := l.root.Stat(key)
	if err != nil {
		return ObjectInfo{}, notFoundOr(err)
	}
	if !fi.Mode().IsRegular() {
		return ObjectInfo{}, ErrNotFound
	}
	return ObjectInfo{Key: key, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

func (l *Local) Delete(_ context.Context, key string) error {
	if !validKey(key) {
		return errBadKey
	}
	if err := l.root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("files: delete: %w", err)
	}
	return nil
}

// List walks the directories under prefix reading entries in batches, so no directory listing is held
// whole; the order is the file system's.
func (l *Local) List(ctx context.Context, prefix string, fn func(ObjectInfo) error) error {
	start := "."
	if i := strings.LastIndexByte(prefix, '/'); i > 0 {
		start = prefix[:i]
	}
	err := l.walk(ctx, start, prefix, fn)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

const listBatch = 256

func (l *Local) walk(ctx context.Context, dir, prefix string, fn func(ObjectInfo) error) error {
	d, err := l.root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }() // only read from
	for {
		entries, err := d.ReadDir(listBatch)
		for _, e := range entries {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			name := e.Name()
			if dir != "." {
				name = dir + "/" + name
			}
			if err := l.visit(ctx, e, name, prefix, fn); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (l *Local) visit(ctx context.Context, e fs.DirEntry, name, prefix string, fn func(ObjectInfo) error) error {
	switch {
	case e.IsDir():
		if name == localTemp || !strings.HasPrefix(name+"/", prefix) && !strings.HasPrefix(prefix, name+"/") {
			return nil
		}
		return l.walk(ctx, name, prefix, fn)
	case !e.Type().IsRegular() || !strings.HasPrefix(name, prefix):
		return nil
	}
	fi, err := e.Info()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fn(ObjectInfo{Key: name, Size: fi.Size(), ModTime: fi.ModTime()})
}

// PruneTemp removes temporary files a crash left behind.
func (l *Local) PruneTemp(ctx context.Context, before time.Time) error {
	entries, err := fs.ReadDir(l.root.FS(), localTemp)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		fi, err := e.Info()
		if err != nil || !fi.ModTime().Before(before) {
			continue
		}
		if err := l.root.Remove(localTemp + "/" + e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func notFoundOr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	return err
}
