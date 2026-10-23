package ids_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type getInput struct {
	ID InvoiceID `path:"id"`
}

type getOutput struct {
	Body struct {
		ID     InvoiceID  `json:"id"`
		Parent *InvoiceID `json:"parent"`
	}
}

func TestHuma_RendersAsUUIDString(t *testing.T) {
	_, api := humatest.New(t)
	huma.Register(api, huma.Operation{OperationID: "get-invoice", Method: http.MethodGet, Path: "/invoices/{id}"},
		func(_ context.Context, in *getInput) (*getOutput, error) {
			out := &getOutput{}
			out.Body.ID = in.ID
			return out, nil
		})

	oas := api.OpenAPI()
	param := oas.Paths["/invoices/{id}"].Get.Parameters[0]
	assert.Equal(t, "string", param.Schema.Type)
	assert.Equal(t, "uuid", param.Schema.Format)

	ref := oas.Paths["/invoices/{id}"].Get.Responses["200"].Content["application/json"].Schema.Ref
	body := oas.Components.Schemas.SchemaFromRef(ref)
	require.NotNil(t, body)
	for _, field := range []string{"id", "parent"} {
		prop := body.Properties[field]
		require.NotNil(t, prop, field)
		assert.Equal(t, "string", prop.Type, field)
		assert.Equal(t, "uuid", prop.Format, field)
	}

	assert.Equal(t, http.StatusUnprocessableEntity, api.Get("/invoices/not-a-uuid").Code, "bad ids fail validation")
	resp := api.Get("/invoices/" + sample)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.JSONEq(t, `{"id":"`+sample+`","parent":null}`, resp.Body.String())
}
