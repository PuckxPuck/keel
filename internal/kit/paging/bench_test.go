package paging_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/paging"
)

// Every list page signs the cursor after its last row, and the next request verifies and decodes it.
func BenchmarkKeysetCursor(b *testing.B) {
	k, err := paging.NewKeyset(db.Postgres, bytes.Repeat([]byte("k"), 32))
	if err != nil {
		b.Fatal(err)
	}
	sort, err := sorts.Resolve("-createdAt", "")
	if err != nil {
		b.Fatal(err)
	}
	rows := make([]joined, 51)
	for i := range rows {
		rows[i] = joined{Item: item{ID: ids.NewOf[itemTag](), CreatedAt: base.Add(time.Duration(i) * time.Second)}}
	}
	filter := map[string]string{"group": "north"}
	b.ReportAllocs()
	for b.Loop() {
		page, err := paging.Trim(rows, 50, sort, filter, k, func(r joined) joined { return r })
		if err != nil {
			b.Fatal(err)
		}
		if _, err := k.After(page.Next, sort, filter); err != nil {
			b.Fatal(err)
		}
	}
}
