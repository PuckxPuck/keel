package db

import (
	"slices"
	"strings"

	"github.com/go-jet/jet/v2/postgres"
)

// DatabaseFilled are columns the database fills on insert (tenant_id from the transaction's tenant,
// change positions from the database clock), so insert column lists leave them out.
var DatabaseFilled = []string{"tenant_id", "change_xid", "changed_at"}

// Insertable returns a table's columns (pass table.AllColumns) minus the database-filled ones.
// postgres.ColumnList and mysql.ColumnList are the same type, so this serves both dialects.
func Insertable(columns postgres.ColumnList) postgres.ColumnList {
	out := make(postgres.ColumnList, 0, len(columns))
	for _, c := range columns {
		if !slices.Contains(DatabaseFilled, c.Name()) {
			out = append(out, c)
		}
	}
	return out
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// LikeEscape escapes LIKE and ILIKE wildcards so user input matches literally (backslash is the escape on both engines).
func LikeEscape(s string) string { return likeEscaper.Replace(s) }
