// Package files stores uploads: streamed under a size cap, typed by content, inspected, kept under random
// keys in local storage or S3, and recorded in the files table.
package files

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type fileTag struct{}

type ID = ids.ID[fileTag]

func ParseID(s string) (ID, error) { return ids.Parse[fileTag](s) }

type Visibility string

const (
	Private Visibility = "private"
	Public  Visibility = "public"
)

// State is where a file is in its life: Put records it pending before its object is written, Stage
// claims it in the caller's transaction, Attach gives it an owner.
type State string

const (
	Pending  State = "pending"
	Staged   State = "staged"
	Attached State = "attached"
)

// Owner is the record a file is attached to.
type Owner struct {
	Type string
	ID   uuid.UUID
}

// Uploader is who sent a file: the principal's subject kind (user, apikey, device) and id, or SystemUploader.
type Uploader struct {
	Kind string
	ID   uuid.UUID
}

// SystemUploader is the actor of jobs and commands; passed to Attach it may attach any staged file.
var SystemUploader = Uploader{Kind: "system"}

func (u Uploader) validate() error {
	if u == SystemUploader {
		return nil
	}
	if u.Kind == "" || len(u.Kind) > maxUploaderKind || u.Kind == SystemUploader.Kind || u.ID == uuid.Nil {
		return errors.New("files: an uploader needs a subject kind and id")
	}
	return nil
}

type File struct {
	ID         ID
	Kind       string
	State      State
	Uploader   Uploader
	Owner      *Owner
	Name       string
	Mime       string
	Size       int64
	SHA256     []byte
	Key        string
	Visibility Visibility
	CreatedAt  time.Time
}

// Receipt is what Put reports about a stored upload; its ID is what the client hands back to be staged.
type Receipt struct {
	ID   ID     `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Mime string `json:"mime"`
	Size int64  `json:"size"`
}

// Policy is what one kind of upload accepts. Types are detected from the content (inspect.Type*).
// Presign lets a public file's link be a storage presigned URL; those cannot carry nosniff or a sandbox
// policy, so leave it off unless the types are inert.
type Policy struct {
	MaxBytes   int64
	Types      []string
	Inspect    bool
	Visibility Visibility
	Presign    bool
}

func (p Policy) validate(kind string) error {
	switch {
	case kind == "" || len(kind) > maxKind:
		return fmt.Errorf("files: kind %q must be 1 to %d characters", kind, maxKind)
	case p.MaxBytes <= 0:
		return fmt.Errorf("files: policy %s needs MaxBytes", kind)
	case len(p.Types) == 0:
		return fmt.Errorf("files: policy %s allows no types", kind)
	case p.Visibility != Private && p.Visibility != Public:
		return fmt.Errorf("files: policy %s needs a visibility", kind)
	}
	return nil
}

const (
	maxKind         = 64
	maxOwnerType    = 64
	maxUploaderKind = 32
	maxName         = 255
	maxKeyPrefix    = 128
)

var (
	ErrNotFound       = errors.New("files: not found")
	ErrUnknownKind    = errors.New("files: unknown upload kind")
	ErrTooLarge       = errors.New("files: upload is too large")
	ErrEmpty          = errors.New("files: upload is empty")
	ErrTypeNotAllowed = errors.New("files: file type is not allowed")
	ErrRefused        = errors.New("files: file refused by inspection")
	ErrNotPublic      = errors.New("files: file is not public")
	ErrBadSignature   = errors.New("files: link is invalid or expired")
)

const (
	CodeTooLarge       = "too_large"
	CodeTypeNotAllowed = "file_type_not_allowed"
	CodeRefused        = "file_refused"
)

// Mapper turns the package's errors into problems. Refusals say what kind of problem the file has, never
// which rule matched.
func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrBadSignature), errors.Is(err, ErrNotPublic):
		return problem.New(http.StatusNotFound, "not_found", "the file does not exist"), true
	case errors.Is(err, ErrTooLarge):
		return problem.New(http.StatusRequestEntityTooLarge, CodeTooLarge, "the file is larger than this upload allows"), true
	case errors.Is(err, ErrTypeNotAllowed), errors.Is(err, ErrEmpty):
		return problem.New(http.StatusUnprocessableEntity, CodeTypeNotAllowed, "this type of file is not accepted here"), true
	case errors.Is(err, ErrRefused):
		return problem.New(http.StatusUnprocessableEntity, CodeRefused, "the file was refused because its content is not safe to keep"), true
	}
	return nil, false
}

type Driver string

const (
	// DriverNone leaves files out: nothing is stored and the upload and download routes are not mounted.
	DriverNone  Driver = ""
	DriverLocal Driver = "local"
	DriverS3    Driver = "s3"
)

// Config is the files part of an app's configuration; field tags follow kit/config.
type Config struct {
	Driver             Driver        `env:"DRIVER"`
	Root               string        `env:"ROOT"`
	TempDir            string        `env:"TEMP_DIR"`
	S3Endpoint         string        `env:"S3_ENDPOINT"`
	S3Bucket           string        `env:"S3_BUCKET"`
	S3Region           string        `env:"S3_REGION"`
	S3AccessKey        string        `env:"S3_ACCESS_KEY"`
	S3SecretKey        config.Secret `env:"S3_SECRET_KEY"`
	S3SSE              bool          `env:"S3_SSE" envDefault:"true"`
	S3PathStyle        bool          `env:"S3_PATH_STYLE"`
	KeyPrefix          string        `env:"KEY_PREFIX"`
	InspectConcurrency int           `env:"INSPECT_CONCURRENCY" envDefault:"2"`
	ImageMaxDecoded    int64         `env:"IMAGE_MAX_DECODED_BYTES" envDefault:"134217728"`
}

// Inspector is the inspector the configuration describes.
func (c Config) Inspector() *inspect.Inspector {
	return inspect.New(inspect.Limits{MaxImageBytes: c.ImageMaxDecoded}, c.InspectConcurrency)
}

func (c Config) Validate(prod bool) error {
	var errs []error
	switch c.Driver {
	case DriverNone:
	case DriverLocal:
		if c.Root == "" || !filepath.IsAbs(c.Root) {
			errs = append(errs, errors.New("root must be an absolute directory for the local driver"))
		}
	case DriverS3:
		errs = append(errs, c.validateS3(prod)...)
	default:
		errs = append(errs, fmt.Errorf("driver must be empty, local or s3, got %q", string(c.Driver)))
	}
	if c.TempDir != "" && !filepath.IsAbs(c.TempDir) {
		errs = append(errs, errors.New("temp dir must be absolute"))
	}
	if c.InspectConcurrency < 1 {
		errs = append(errs, errors.New("inspect concurrency must be at least 1"))
	}
	if c.ImageMaxDecoded < 1 {
		errs = append(errs, errors.New("image max decoded bytes must be positive"))
	}
	if !validPrefix(c.KeyPrefix) {
		errs = append(errs, errors.New("key prefix must be empty or key segments ending in a slash"))
	}
	return errors.Join(errs...)
}

func (c Config) validateS3(prod bool) []error {
	var errs []error
	if c.S3Bucket == "" || c.S3Region == "" {
		errs = append(errs, errors.New("s3 bucket and region are required for the s3 driver"))
	}
	if c.S3Endpoint != "" {
		u, err := url.Parse(c.S3Endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, errors.New("s3 endpoint must be an absolute http(s) URL"))
		} else if prod && u.Scheme != "https" {
			errs = append(errs, errors.New("s3 endpoint must be https in production"))
		}
	}
	if (c.S3AccessKey == "") != (c.S3SecretKey == "") {
		errs = append(errs, errors.New("s3 access key and secret key are set together"))
	}
	if c.S3SecretKey != "" {
		if err := config.RequireStrong("s3 secret key", c.S3SecretKey, prod); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Enabled reports whether a driver is configured.
func (c Config) Enabled() bool { return c.Driver != DriverNone }

// Open returns the storage the configuration names.
func Open(ctx context.Context, c Config) (Storage, error) {
	switch c.Driver {
	case DriverNone:
		return nil, errors.New("files: no driver is configured")
	case DriverLocal:
		return NewLocal(c.Root)
	case DriverS3:
		return NewS3(ctx, S3Options{
			Endpoint: c.S3Endpoint, Bucket: c.S3Bucket, Region: c.S3Region, AccessKey: c.S3AccessKey,
			SecretKey: c.S3SecretKey, DisableSSE: !c.S3SSE, PathStyle: c.S3PathStyle,
		})
	}
	return nil, fmt.Errorf("files: driver %q is not local or s3", string(c.Driver))
}
