// Package paging builds keyset and offset pages over Jet queries. Expressions come from Jet's
// dialect-neutral core (postgres.Column and mysql.Column are the same type), so one Sorts value serves both.
package paging

import (
	"errors"
	"strings"

	"github.com/go-jet/jet/v2/postgres"
)

type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Detail }

var (
	ErrCursorInvalid  = &Error{Code: "cursor_invalid", Detail: "the cursor is not valid; start again from the first page"}
	ErrCursorMismatch = &Error{Code: "cursor_mismatch", Detail: "the cursor was made for another sort or filter"}
	ErrUnknownSort    = &Error{Code: "unknown_sort", Detail: "sort is not one of the allowed values"}
	ErrTooDeep        = &Error{Code: "page_too_deep", Detail: "the page is past the deepest offset allowed; use the cursor instead"}

	errBadSort = errors.New("paging: a sort needs keys with a column and a value, ending with a not-null unique key")
)

// Key is one sort column and how to read its value from a row of type T. Value returns a uuid (or typed
// id), an integer, a bool, a string, a time, a decimal or a driver.Valuer of one of those; nil for NULL,
// which only a Nullable key may hold (Opt turns a pointer into a value or nil).
type Key[T any] struct {
	Column   postgres.Column
	Value    func(T) any
	Nullable bool
}

// Sorts maps the allowed values of a list's sort parameter to keys. The last key must be unique and not
// null (the id) so the order is total. Nulls sort last in both directions.
type Sorts[T any] map[string][]Key[T]

// Opt is a nullable key's value: nil for a nil pointer, else what it points to.
func Opt[V any](p *V) any {
	if p == nil {
		return nil
	}
	return *p
}

// Sort is a resolved sort: "-issuedOn" is issuedOn descending.
type Sort[T any] struct {
	key  string
	desc bool
	keys []Key[T]
}

// Ordering is a resolved sort of any row type, as Keyset.After takes it.
type Ordering interface {
	ordering() (key string, desc bool, cols []postgres.Column, nullable []bool)
}

// Resolve picks the sort named by param, or def when param is empty.
func (s Sorts[T]) Resolve(param, def string) (Sort[T], error) {
	if param == "" {
		param = def
	}
	name, desc := strings.CutPrefix(param, "-")
	keys, ok := s[name]
	if !ok {
		return Sort[T]{}, ErrUnknownSort
	}
	if len(keys) == 0 || keys[len(keys)-1].Nullable {
		return Sort[T]{}, errBadSort
	}
	for _, k := range keys {
		if k.Column == nil || k.Value == nil {
			return Sort[T]{}, errBadSort
		}
	}
	return Sort[T]{key: param, desc: desc, keys: keys}, nil
}

func (s Sort[T]) Key() string { return s.key }

func (s Sort[T]) ordering() (string, bool, []postgres.Column, []bool) {
	cols := make([]postgres.Column, len(s.keys))
	nullable := make([]bool, len(s.keys))
	for i, k := range s.keys {
		cols[i], nullable[i] = k.Column, k.Nullable
	}
	return s.key, s.desc, cols, nullable
}

func (s Sort[T]) OrderBy() []postgres.OrderByClause {
	out := make([]postgres.OrderByClause, len(s.keys))
	for i, k := range s.keys {
		clause := k.Column.ASC()
		if s.desc {
			clause = k.Column.DESC()
		}
		if k.Nullable {
			clause = clause.NULLS_LAST()
		}
		out[i] = clause
	}
	return out
}
