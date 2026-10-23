package ids

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid id")

// errNotCanonical never carries the input: Huma copies parser errors into responses.
var (
	errNotCanonical = fmt.Errorf("%w: expected a canonical uuid (8-4-4-4-12 hex digits)", ErrInvalid)
	errZero         = fmt.Errorf("%w: the all-zero uuid is not an id", ErrInvalid)
)

// New returns a UUIDv7; it panics only if the operating system's random source fails.
func New() uuid.UUID {
	u, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Errorf("ids: random source failed: %w", err))
	}
	return u
}

// Stable returns the UUIDv5 of name in namespace, for deterministic seeds and imports.
func Stable(namespace uuid.UUID, name string) uuid.UUID {
	return uuid.NewSHA1(namespace, []byte(name))
}

// ID is a UUID tied to an entity type T, so ids of different entities do not mix.
type ID[T any] [16]byte

func NewOf[T any]() ID[T] { return ID[T](New()) }

func FromUUID[T any](u uuid.UUID) ID[T] { return ID[T](u) }

// Parse accepts only the canonical 36-character form, and never the all-zero uuid.
func Parse[T any](s string) (ID[T], error) {
	if len(s) != 36 {
		return ID[T]{}, errNotCanonical
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return ID[T]{}, errNotCanonical
	}
	if u == uuid.Nil {
		return ID[T]{}, errZero
	}
	return ID[T](u), nil
}

func MustParse[T any](s string) ID[T] {
	id, err := Parse[T](s)
	if err != nil {
		panic(err)
	}
	return id
}

func (id ID[T]) UUID() uuid.UUID { return uuid.UUID(id) }
func (id ID[T]) String() string  { return uuid.UUID(id).String() }
func (id ID[T]) IsZero() bool    { return id == ID[T]{} }

// MarshalText refuses the zero id so an unset id never leaves the process; optional references use *ID.
func (id ID[T]) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, errZero
	}
	return []byte(id.String()), nil
}

func (id *ID[T]) UnmarshalText(text []byte) error {
	parsed, err := Parse[T](string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Scan accepts the text form and the raw 16-byte form; NULL gives the zero id.
func (id *ID[T]) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*id = ID[T]{}
		return nil
	case string:
		return id.UnmarshalText([]byte(v))
	case []byte:
		if len(v) != 16 {
			return id.UnmarshalText(v)
		}
		if uuid.UUID(v) == uuid.Nil {
			return errZero
		}
		copy(id[:], v)
		return nil
	default:
		return fmt.Errorf("%w: cannot scan %T", ErrInvalid, src)
	}
}

// Value is the text form, which both Postgres uuid and MySQL char(36) accept (D6). The zero id is an
// error, never NULL: an optional reference is a *ID, which database/sql already stores as NULL.
func (id ID[T]) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, errZero
	}
	return id.String(), nil
}

// Param binds the id in a Jet statement on either engine. Jet's UUID(id) binds the zero id as the
// all-zero uuid; Param binds the id itself, so Value refuses the zero id when the statement runs.
func (id ID[T]) Param() postgres.StringExpression {
	return postgres.StringExp(postgres.Raw("#id", postgres.RawArgs{"#id": id}))
}

func (ID[T]) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Format: "uuid"}
}
