package httpx_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

type widget struct {
	Name string `json:"name"`
}

type idInput struct {
	ID string `path:"id"`
}

type bareOutput struct {
	Body struct {
		Name string `json:"name"`
	}
}

func TestCheckOutputs_NamesEveryOperationOutsideTheEnvelopes(t *testing.T) {
	api := httpx.NewAPI(httpx.NewRouter(), httpx.Options{Title: "t", Version: "1", BasePath: "/api/v1"})
	huma.Register(api, huma.Operation{OperationID: "getWidget", Method: http.MethodGet, Path: "/widgets/{id}"},
		func(context.Context, *idInput) (*httpx.One[widget], error) { return httpx.OneOf(widget{}), nil })
	huma.Register(api, huma.Operation{OperationID: "listWidgets", Method: http.MethodGet, Path: "/widgets"},
		func(context.Context, *struct{}) (*httpx.List[widget], error) {
			return httpx.ListOf[widget](nil, httpx.ListMeta{}, httpx.Links{}), nil
		})
	huma.Register(api, huma.Operation{OperationID: "widgetChanges", Method: http.MethodGet, Path: "/widgets/changes"},
		func(context.Context, *struct{}) (*httpx.Feed[widget], error) { return &httpx.Feed[widget]{}, nil })
	huma.Register(api, huma.Operation{OperationID: "deleteWidget", Method: http.MethodDelete, Path: "/widgets/{id}"},
		func(context.Context, *idInput) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil })
	require.NoError(t, httpx.CheckOutputs(api))

	huma.Register(api, huma.Operation{OperationID: "bareWidget", Method: http.MethodGet, Path: "/bare"},
		func(context.Context, *struct{}) (*bareOutput, error) { return &bareOutput{}, nil })
	huma.Register(api, huma.Operation{OperationID: "bareDelete", Method: http.MethodPost, Path: "/bare-delete"},
		func(context.Context, *struct{}) (*struct{ Body []widget }, error) { return nil, nil })
	huma.Register(api, huma.Operation{OperationID: "unpagedList", Method: http.MethodGet, Path: "/unpaged"},
		func(context.Context, *struct{}) (*httpx.One[[]widget], error) { return httpx.OneOf([]widget{}), nil })
	huma.Register(api, huma.Operation{OperationID: "hiddenBare", Method: http.MethodGet, Path: "/hidden-bare", Hidden: true},
		func(context.Context, *struct{}) (*bareOutput, error) { return &bareOutput{}, nil })

	err := httpx.CheckOutputs(api)

	require.Error(t, err)
	require.ErrorContains(t, err, "bareWidget")
	require.ErrorContains(t, err, "bareDelete")
	require.ErrorContains(t, err, "unpagedList")
	require.ErrorContains(t, err, "hiddenBare")
	assert.NotContains(t, err.Error(), "getWidget")
	assert.NotContains(t, err.Error(), "listWidgets")
	assert.NotContains(t, err.Error(), "widgetChanges")
}

type createWidgetInput struct {
	Again bool `query:"again"`
}

// A Created output answers 201 or 200 in the data envelope, and the document lists both.
func TestCreated_AnswersAndDocumentsBothStatuses(t *testing.T) {
	router := httpx.NewRouter()
	api := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1"})
	httpx.Register(api, huma.Operation{OperationID: "createWidget", Method: http.MethodPost, Path: "/widgets"},
		func(_ context.Context, in *createWidgetInput) (*httpx.Created[widget], error) {
			return httpx.CreatedOf(widget{Name: "w"}, !in.Again), nil
		})

	for query, want := range map[string]int{"": http.StatusCreated, "?again=true": http.StatusOK} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/widgets"+query, nil))
		assert.Equal(t, want, rec.Code, query)
		assert.JSONEq(t, `{"data":{"name":"w"}}`, rec.Body.String())
	}
	op := api.OpenAPI().Paths["/widgets"].Post
	assert.Contains(t, op.Responses, "200")
	assert.Contains(t, op.Responses, "201")
	require.NoError(t, httpx.CheckOutputs(api))
}

func TestList_EmptyDataIsAnArrayNotNull(t *testing.T) {
	out, err := json.Marshal(httpx.ListOf[widget](nil, httpx.ListMeta{Limit: 50}, httpx.Links{}).Body)

	require.NoError(t, err)
	assert.JSONEq(t, `{"data":[],"meta":{"limit":50,"total":null,"totalCapped":false},"links":{"next":null,"prev":null}}`, string(out))
}

func BenchmarkListEnvelope(b *testing.B) {
	items := make([]widget, 50)
	for i := range items {
		items[i] = widget{Name: "widget"}
	}
	total := len(items)
	next := "cursor"
	body := httpx.ListOf(items, httpx.ListMeta{Limit: 50, Total: &total}, httpx.Links{Next: &next}).Body
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(body); err != nil {
			b.Fatal(err)
		}
	}
}
