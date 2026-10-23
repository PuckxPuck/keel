package paging

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jet/jet/v2/postgres"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

const (
	minKeyBytes    = 32
	maxCursorBytes = 2048
)

// Keyset signs and verifies cursors. The first key signs; every key verifies, so keys rotate by
// prepending a new one and dropping the oldest later.
type Keyset struct {
	dialect db.Dialect
	keys    [][]byte
}

func NewKeyset(dialect db.Dialect, keys ...[]byte) (*Keyset, error) {
	if len(keys) == 0 {
		return nil, errors.New("paging: at least one cursor key is required")
	}
	for _, k := range keys {
		if len(k) < minKeyBytes {
			return nil, fmt.Errorf("paging: cursor keys must be at least %d bytes", minKeyBytes)
		}
	}
	return &Keyset{dialect: dialect, keys: keys}, nil
}

// cursor carries the sort (with its direction), a hash of the filters, and the last row's sort values;
// the id is the last value because the id is the last sort column.
type cursor struct {
	Sort   string   `json:"s"`
	Filter string   `json:"f"`
	Values []*value `json:"v"`
}

// After verifies a cursor against the sort and filter of this request and returns the condition
// selecting the rows after it. An empty cursor is the first page.
func (k *Keyset) After(token string, sort Ordering, filter any) (postgres.BoolExpression, error) {
	if token == "" {
		return postgres.RawBool("TRUE"), nil
	}
	c, err := k.decode(token)
	if err != nil {
		return nil, err
	}
	hash, err := filterHash(filter)
	if err != nil {
		return nil, err
	}
	o := resolved(sort)
	if c.Sort != o.key || c.Filter != hash {
		return nil, ErrCursorMismatch
	}
	if len(c.Values) != len(o.cols) || c.Values[len(c.Values)-1] == nil {
		return nil, ErrCursorInvalid
	}
	params := make([]postgres.Expression, len(c.Values))
	for i, v := range c.Values {
		if v == nil {
			if !o.nullable[i] {
				return nil, ErrCursorInvalid
			}
			continue
		}
		bound, err := decodeValue(*v, k.dialect)
		if err != nil {
			return nil, ErrCursorInvalid
		}
		params[i] = postgres.Raw("#v", postgres.RawArgs{"#v": bound})
	}
	return condition(k.dialect, o, params), nil
}

type order struct {
	key      string
	desc     bool
	cols     []postgres.Column
	nullable []bool
}

func resolved(s Ordering) order {
	var o order
	o.key, o.desc, o.cols, o.nullable = s.ordering()
	return o
}

func (o order) hasNullable() bool {
	for _, n := range o.nullable {
		if n {
			return true
		}
	}
	return false
}

func (k *Keyset) encode(c cursor) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("paging: encode cursor: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sign(k.keys[0], payload)), nil
}

func (k *Keyset) decode(token string) (cursor, error) {
	if len(token) > maxCursorBytes {
		return cursor{}, ErrCursorInvalid
	}
	body, mac, ok := strings.Cut(token, ".")
	if !ok {
		return cursor{}, ErrCursorInvalid
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(body)
	if err != nil {
		return cursor{}, ErrCursorInvalid
	}
	sig, err := enc.DecodeString(mac)
	if err != nil {
		return cursor{}, ErrCursorInvalid
	}
	verified := false
	for _, key := range k.keys {
		if hmac.Equal(sig, sign(key, payload)) {
			verified = true
			break
		}
	}
	if !verified {
		return cursor{}, ErrCursorInvalid
	}
	var c cursor
	if err := json.Unmarshal(payload, &c); err != nil || len(c.Values) == 0 {
		return cursor{}, ErrCursorInvalid
	}
	return c, nil
}

func sign(key, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	return h.Sum(nil)
}

func filterHash(filter any) (string, error) {
	raw, err := json.Marshal(filter)
	if err != nil {
		return "", fmt.Errorf("paging: hash filter: %w", err)
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:12]), nil
}

// condition selects rows strictly after the cursor in sort order. Postgres compares rows, which uses
// the index; MySQL does not use indexes well for row comparison, so it gets the expanded form, as do
// sorts with nullable columns (nulls sort last).
func condition(dialect db.Dialect, sort order, params []postgres.Expression) postgres.BoolExpression {
	if dialect == db.Postgres && !sort.hasNullable() {
		left := make([]postgres.Expression, len(sort.cols))
		for i, c := range sort.cols {
			left[i] = c
		}
		if sort.desc {
			return postgres.ROW(left...).LT(postgres.ROW(params...))
		}
		return postgres.ROW(left...).GT(postgres.ROW(params...))
	}
	op := " > "
	if sort.desc {
		op = " < "
	}
	var terms []postgres.BoolExpression
	for i := range sort.cols {
		after := afterOn(sort, i, op, params[i])
		if after == nil {
			continue
		}
		term := after
		for j := i - 1; j >= 0; j-- {
			term = equalOn(sort.cols[j], params[j]).AND(term)
		}
		terms = append(terms, term)
	}
	if len(terms) == 0 {
		return postgres.RawBool("FALSE")
	}
	return postgres.OR(terms...)
}

func afterOn(sort order, i int, op string, p postgres.Expression) postgres.BoolExpression {
	if p == nil {
		return nil
	}
	c := sort.cols[i]
	after := postgres.BoolExp(postgres.CustomExpression(c, postgres.Token(op), p))
	if sort.nullable[i] {
		return postgres.OR(after, c.IS_NULL())
	}
	return after
}

func equalOn(c postgres.Column, p postgres.Expression) postgres.BoolExpression {
	if p == nil {
		return c.IS_NULL()
	}
	return postgres.BoolExp(postgres.CustomExpression(c, postgres.Token(" = "), p))
}
