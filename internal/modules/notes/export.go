package notes

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/xlsx"
)

const xlsxType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

// exportInput documents the query; httpx.Serve hands the request to export before Huma reads it, so
// export checks the same bounds itself.
type exportInput struct {
	Sort   string `query:"sort" enum:"title,-title,createdAt,-createdAt,updatedAt,-updatedAt" default:"-updatedAt"`
	Status string `query:"status" enum:"active,archived"`
	Q      string `query:"q" minLength:"2" maxLength:"100"`
}

// exportBody is the spreadsheet, as the document describes it.
type exportBody struct {
	Body []byte
}

func exportOperation(op huma.Operation) huma.Operation {
	op.Responses = map[string]*huma.Response{"200": {Description: "The notes as an xlsx workbook", Content: map[string]*huma.MediaType{
		xlsxType: {Schema: &huma.Schema{Type: "string", Format: "binary"}},
	}}}
	return op
}

// servedByHandler is never called: httpx.Serve answers first.
func servedByHandler[I any](context.Context, *I) (*exportBody, error) {
	return nil, errors.New("served by its http.Handler")
}

var errBadQuery = problem.New(http.StatusBadRequest, "invalid_query", "status must be active or archived, and q 2 to 100 characters")

// export writes the workbook only once every row is in, so a refusal part way is still a problem answer.
// Text cells are neutralised by kit/xlsx, so a title like =HYPERLINK(...) stays text.
func (h handlers) export() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.svc.db == nil {
			problem.Write(w, r, errUnavailable)
			return
		}
		q := r.URL.Query()
		f := Filter{Status: Status(q.Get("status")), Query: q.Get("q")}
		if (f.Status != "" && f.Status != StatusActive && f.Status != StatusArchived) ||
			(f.Query != "" && (utf8.RuneCountInString(f.Query) < 2 || utf8.RuneCountInString(f.Query) > 100)) {
			problem.Write(w, r, errBadQuery)
			return
		}
		book, err := xlsx.NewWriter(w)
		if err == nil {
			err = book.Sheet("Notes")
		}
		if err == nil {
			err = book.Row("Title", "Status", "Words", "Attachment", "Created", "Updated", "Body")
		}
		if err == nil {
			err = h.svc.Export(r.Context(), f, q.Get("sort"), func(n Note) error {
				var words, attachment any
				if n.WordCount != nil {
					words = *n.WordCount
				}
				if n.Attachment != nil {
					attachment = n.Attachment.Name
				}
				return book.Row(n.Title, string(n.Status), words, attachment, n.CreatedAt, n.UpdatedAt, n.Body)
			})
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", xlsxType)
		w.Header().Set("Content-Disposition", files.ContentDisposition("notes.xlsx"))
		if err := book.Close(); err != nil {
			logx.From(r.Context()).Warn("notes: export cut short", slog.Any("error", err))
		}
	})
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	if p, ok := paging.Mapper(err); ok {
		problem.Write(w, r, p)
		return
	}
	if p, ok := mapError(err); ok {
		problem.Write(w, r, p)
		return
	}
	logx.From(r.Context()).Error("notes: export", slog.Any("error", err))
	problem.Write(w, r, problem.Internal())
}
