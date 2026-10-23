package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

type OneBody[T any] struct {
	Data T `json:"data"`
}

// One is the output of an operation that returns a single resource.
type One[T any] struct {
	Body OneBody[T]
}

func OneOf[T any](v T) *One[T] { return &One[T]{Body: OneBody[T]{Data: v}} }

type ListMeta struct {
	Limit       int  `json:"limit"`
	Total       *int `json:"total" nullable:"true" doc:"Present only when the operation offers totals; capped"`
	TotalCapped bool `json:"totalCapped"`
	Page        *int `json:"page,omitempty" doc:"Offset pagination only"`
	Pages       *int `json:"pages,omitempty" doc:"Offset pagination only"`
}

type Links struct {
	Next *string `json:"next" nullable:"true"`
	Prev *string `json:"prev" nullable:"true"`
}

type ListBody[T any] struct {
	Data  []T      `json:"data"`
	Meta  ListMeta `json:"meta"`
	Links Links    `json:"links"`
}

// MarshalJSON writes an empty list as [] rather than null.
func (b ListBody[T]) MarshalJSON() ([]byte, error) {
	type plain ListBody[T]
	if b.Data == nil {
		b.Data = []T{}
	}
	return json.Marshal(plain(b))
}

// List is the output of a paginated list operation.
type List[T any] struct {
	Body ListBody[T]
}

func ListOf[T any](items []T, meta ListMeta, links Links) *List[T] {
	return &List[T]{Body: ListBody[T]{Data: items, Meta: meta, Links: links}}
}

type FeedOp string

const (
	FeedUpsert FeedOp = "upsert"
	FeedDelete FeedOp = "delete"
)

type FeedEntry[T any] struct {
	Op      FeedOp `json:"op" enum:"upsert,delete"`
	ID      string `json:"id" format:"uuid"`
	Version int64  `json:"version"`
	Record  *T     `json:"record,omitempty" doc:"Absent for deletes"`
}

type FeedMeta struct {
	Limit   int  `json:"limit"`
	HasMore bool `json:"hasMore"`
}

type FeedLinks struct {
	Next string `json:"next" doc:"Token to store after the page is applied"`
}

type FeedBody[T any] struct {
	Data  []FeedEntry[T] `json:"data"`
	Meta  FeedMeta       `json:"meta"`
	Links FeedLinks      `json:"links"`
}

// MarshalJSON writes an empty feed page as [] rather than null.
func (b FeedBody[T]) MarshalJSON() ([]byte, error) {
	type plain FeedBody[T]
	if b.Data == nil {
		b.Data = []FeedEntry[T]{}
	}
	return json.Marshal(plain(b))
}

// Feed is the output of a change-feed operation.
type Feed[T any] struct {
	Body FeedBody[T]
}

// Created is the output of a create that answers 201 with the new resource, or 200 with the one already
// stored when the client sends it again (a client-made id seen before). Register documents both.
type Created[T any] struct {
	Status int
	Body   OneBody[T]
}

// CreatedOf answers 201 when created is true, otherwise 200.
func CreatedOf[T any](v T, created bool) *Created[T] {
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return &Created[T]{Status: status, Body: OneBody[T]{Data: v}}
}

func (Created[T]) answersExisting() {}

type answersExisting interface{ answersExisting() }

// documentExisting makes 201 the operation's status and adds the 200 a Created output may answer.
func documentExisting(api huma.API, op *huma.Operation, body reflect.Type) {
	if op.DefaultStatus == 0 {
		op.DefaultStatus = http.StatusCreated
	}
	if op.Responses == nil {
		op.Responses = map[string]*huma.Response{}
	}
	if _, ok := op.Responses["200"]; ok {
		return
	}
	schema := api.OpenAPI().Components.Schemas.Schema(body, true, op.OperationID+"Response")
	op.Responses["200"] = &huma.Response{
		Description: "Already stored: the resource as it is",
		Content:     map[string]*huma.MediaType{"application/json": {Schema: schema}},
	}
}

// NoContent is the output of an operation that answers 204.
type NoContent struct{}

// CheckOutputs reports every operation, hidden ones included, whose 2xx response is not one of the envelopes.
func CheckOutputs(api huma.API) error {
	schemas := api.OpenAPI().Components.Schemas
	var errs []error
	for _, op := range Operations(api) {
		for status, resp := range op.Responses {
			if isServed(op) && resp.Content["application/json"] == nil {
				continue
			}
			if reason := envelopeViolation(schemas, status, resp); reason != "" {
				errs = append(errs, fmt.Errorf("%s %s (%s) response %s: %s", op.Method, op.Path, op.OperationID, status, reason))
			}
		}
	}
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return errors.Join(errs...)
}

func envelopeViolation(reg huma.Registry, status string, resp *huma.Response) string {
	code, err := strconv.Atoi(status)
	if err != nil || code < 200 || code > 299 {
		return ""
	}
	if code == http.StatusNoContent {
		if len(resp.Content) > 0 {
			return "204 must have no body"
		}
		return ""
	}
	media := resp.Content["application/json"]
	if len(resp.Content) != 1 || media == nil || media.Schema == nil {
		return "body must be application/json in the data envelope"
	}
	schema := resolve(reg, media.Schema)
	if schema == nil || schema.Type != "object" || !slices.Contains(schema.Required, "data") {
		return "body is not an envelope with a required data member"
	}
	data := resolve(reg, schema.Properties["data"])
	if data == nil {
		return "body is not an envelope with a required data member"
	}
	for name := range schema.Properties {
		if name != "data" && name != "meta" && name != "links" {
			return fmt.Sprintf("envelope has the unexpected member %q", name)
		}
	}
	switch data.Type {
	case "object":
		if len(schema.Properties) > 1 {
			return "a single resource carries only data"
		}
	case "array":
		if !slices.Contains(schema.Required, "meta") || !slices.Contains(schema.Required, "links") {
			return "a list must use List or Feed so it carries meta and links"
		}
	default:
		return "data must be an object or an array"
	}
	return ""
}

func resolve(reg huma.Registry, s *huma.Schema) *huma.Schema {
	for range 8 {
		if s == nil || s.Ref == "" {
			return s
		}
		s = reg.SchemaFromRef(s.Ref)
	}
	return nil
}
