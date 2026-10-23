package paging

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/go-jet/jet/v2/qrm"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

// Request is what a list operation reads from its query parameters.
type Request struct {
	Limit  int
	Cursor string
	Sort   string
}

// Page is one page of a keyset list; Next is empty on the last page.
type Page[T any] struct {
	Items []T
	Next  string
}

// Trim turns the limit+1 rows a store fetched into a page and the cursor after its last row.
func Trim[T, R any](rows []T, limit int, sort Sort[T], filter any, k *Keyset, conv func(T) R) (Page[R], error) {
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	page := Page[R]{Items: make([]R, len(rows))}
	for i, r := range rows {
		page.Items[i] = conv(r)
	}
	if !more || limit == 0 {
		return page, nil
	}
	last := rows[len(rows)-1]
	values := make([]*value, len(sort.keys))
	for i, key := range sort.keys {
		v, err := encodeValue(key.Value(last))
		if err != nil {
			return Page[R]{}, err
		}
		if v == nil && !key.Nullable {
			return Page[R]{}, fmt.Errorf("paging: sort %s read NULL from a key not marked Nullable", sort.key)
		}
		values[i] = v
	}
	hash, err := filterHash(filter)
	if err != nil {
		return Page[R]{}, err
	}
	if page.Next, err = k.encode(cursor{Sort: sort.key, Filter: hash, Values: values}); err != nil {
		return Page[R]{}, err
	}
	return page, nil
}

// List is the page as the list envelope; links.next is self with its cursor parameter replaced.
func (p Page[T]) List(limit int, self *url.URL) *httpx.List[T] {
	var links httpx.Links
	if p.Next != "" {
		next := *self
		q := next.Query()
		q.Set("cursor", p.Next)
		next.RawQuery = q.Encode()
		s := next.String()
		links.Next = &s
	}
	return httpx.ListOf(p.Items, httpx.ListMeta{Limit: limit}, links)
}

// Offset is a numbered page, for lists that need page numbers; prefer keyset pages.
type Offset struct {
	Page  int
	Limit int
}

// Skip validates the page against maxDepth rows and returns the rows to skip.
func (o Offset) Skip(maxDepth int) (int64, error) {
	if o.Page < 1 || o.Limit < 1 {
		return 0, errors.New("paging: page and limit start at 1")
	}
	if o.Page > maxDepth/o.Limit {
		return 0, ErrTooDeep
	}
	return int64(o.Page-1) * int64(o.Limit), nil
}

// CappedTotal counts the rows of base (a SELECT without ORDER BY or LIMIT) up to limit, so a count
// never scans a whole large table. capped is true when there are more than limit rows.
func CappedTotal(ctx context.Context, q qrm.Queryable, base postgres.Statement, limit int) (total int, capped bool, err error) {
	query, args := base.Sql()
	query = strings.TrimSuffix(strings.TrimSpace(query), ";")
	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM (%s LIMIT %d) AS capped", query, limit+1), args...)
	if err != nil {
		return 0, false, fmt.Errorf("count: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, false, fmt.Errorf("count: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, false, fmt.Errorf("count: %w", err)
	}
	if total > limit {
		return limit, true, nil
	}
	return total, false, nil
}
