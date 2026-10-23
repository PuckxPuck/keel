package problem_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

var errLocked = errors.New("invoice 7 is locked by someone")

type createInput struct {
	Body struct {
		Email string `json:"email" format:"email"`
		Name  string `json:"name" minLength:"3" maxLength:"10"`
		Age   int    `json:"age" minimum:"18"`
		Lines []struct {
			Qty int `json:"qty" minimum:"1"`
		} `json:"lines"`
	}
	Limit int `query:"limit" maximum:"100" default:"10"`
}

func newTestAPI(t *testing.T) http.Handler {
	t.Helper()
	problem.Install(func(err error) (*problem.Problem, bool) {
		if !errors.Is(err, errLocked) {
			return nil, false
		}
		p := problem.New(http.StatusConflict, "locked", "the invoice is locked")
		p.Extensions = map[string]any{"lockedBy": "ops", "errors": "spoofed"}
		return p, true
	})
	router := httpx.NewRouter()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := problem.WithRequestID(logx.WithLogger(r.Context(), logger), "req-12345678")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	api := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1"})
	huma.Register(api, huma.Operation{OperationID: "create", Method: http.MethodPost, Path: "/things"},
		func(context.Context, *createInput) (*struct{}, error) { return nil, nil })
	huma.Register(api, huma.Operation{OperationID: "locked", Method: http.MethodGet, Path: "/locked"},
		func(context.Context, *struct{}) (*struct{}, error) { return nil, errLocked })
	huma.Register(api, huma.Operation{OperationID: "broken", Method: http.MethodGet, Path: "/broken"},
		func(context.Context, *struct{}) (*struct{}, error) {
			return nil, errors.New("pq: password authentication failed for user app")
		})
	huma.Register(api, huma.Operation{OperationID: "missing", Method: http.MethodGet, Path: "/missing"},
		func(context.Context, *struct{}) (*struct{}, error) {
			return nil, huma.Error404NotFound("no such thing")
		})
	return router
}

func do(t *testing.T, h http.Handler, method, target, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return rec, out
}

func TestValidationErrors_HaveLocationsAndNeverEchoValues(t *testing.T) {
	h := newTestAPI(t)
	body := `{"email":"leaky-secret@@x","name":"ab","age":3,"lines":[{"qty":1},{"qty":0}],"extra":"leaky-extra"}`

	rec, out := do(t, h, http.MethodPost, "/things?limit=500", body)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "validation_failed", out["code"])
	assert.Equal(t, "req-12345678", out["requestId"])
	got := map[string]string{}
	for _, e := range out["errors"].([]any) {
		m := e.(map[string]any)
		got[m["location"].(string)] = m["code"].(string)
	}
	assert.Equal(t, map[string]string{
		"body.email":        "format",
		"body.name":         "min_length",
		"body.age":          "minimum",
		"body.lines[1].qty": "minimum",
		"body.extra":        "unknown_field",
		"query.limit":       "maximum",
	}, got)
	assert.NotContains(t, rec.Body.String(), "leaky-secret")
	assert.NotContains(t, rec.Body.String(), "500")
}

func TestValidationErrors_UnknownFieldLocationIsCapped(t *testing.T) {
	key := strings.Repeat("k", 4096)
	rec, out := do(t, newTestAPI(t), http.MethodPost, "/things", `{"email":"a@example.com","name":"abc","age":20,"lines":[],"`+key+`":1}`)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	errs := out["errors"].([]any)
	require.Len(t, errs, 1)
	assert.Equal(t, "unknown_field", errs[0].(map[string]any)["code"])
	assert.LessOrEqual(t, len(errs[0].(map[string]any)["location"].(string)), 64)
}

func TestValidationErrors_MissingRequiredFieldNamesTheField(t *testing.T) {
	_, out := do(t, newTestAPI(t), http.MethodPost, "/things", `{}`)

	locations := map[string]string{}
	for _, e := range out["errors"].([]any) {
		m := e.(map[string]any)
		locations[m["location"].(string)] = m["code"].(string)
	}
	assert.Equal(t, "required", locations["body.email"])
}

func TestInvalidJSON_IsA400WithoutTheBody(t *testing.T) {
	rec, out := do(t, newTestAPI(t), http.MethodPost, "/things", `{"email": "leaky-secret"`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_json", out["code"])
	assert.NotContains(t, rec.Body.String(), "leaky-secret")
}

func TestMappers_TurnDomainErrorsIntoProblems(t *testing.T) {
	h := newTestAPI(t)

	rec, out := do(t, h, http.MethodGet, "/locked", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "locked", out["code"])
	assert.Equal(t, "ops", out["lockedBy"])
	assert.NotContains(t, out, "errors", "extensions cannot set a standard member")
	assert.Equal(t, "req-12345678", out["requestId"])
	assert.NotContains(t, rec.Body.String(), "invoice 7")

	rec, out = do(t, h, http.MethodGet, "/missing", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "not_found", out["code"])
}

func TestUnmappedErrors_AreGenericInternal(t *testing.T) {
	rec, out := do(t, newTestAPI(t), http.MethodGet, "/broken", "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "internal", out["code"])
	assert.Equal(t, "internal error", out["detail"])
	assert.NotContains(t, rec.Body.String(), "password")
}

func TestOversizedStreamedBody_Is413(t *testing.T) {
	h := httpx.MaxBody(16)(newTestAPI(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/things", strings.NewReader(`{"name":"`+strings.Repeat("a", 64)+`"}`))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Contains(t, rec.Body.String(), `"code":"too_large"`)
}
