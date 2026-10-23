package dates_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/dates"
)

type dueInput struct {
	Due dates.Date `query:"due"`
}

type dueOutput struct {
	Body struct {
		Due dates.Date `json:"due"`
	}
}

func TestHuma_RendersAsDateString(t *testing.T) {
	_, api := humatest.New(t)
	huma.Register(api, huma.Operation{OperationID: "due", Method: http.MethodGet, Path: "/due"},
		func(_ context.Context, in *dueInput) (*dueOutput, error) {
			out := &dueOutput{}
			out.Body.Due = in.Due
			return out, nil
		})

	param := api.OpenAPI().Paths["/due"].Get.Parameters[0]
	require.NotNil(t, param.Schema)
	assert.Equal(t, "string", param.Schema.Type)
	assert.Equal(t, "date", param.Schema.Format)
	assert.Equal(t, http.StatusUnprocessableEntity, api.Get("/due?due=2026-02-30").Code)
	assert.Equal(t, http.StatusOK, api.Get("/due?due=2026-10-22").Code)
}
