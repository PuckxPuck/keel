package problem

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
)

const ContentType = "application/problem+json"

const (
	CodeInternal         = "internal"
	CodeValidationFailed = "validation_failed"
	CodeNotFound         = "not_found"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeForbidden        = "forbidden"
	CodeTooLarge         = "too_large"
	CodeInvalidJSON      = "invalid_json"
	CodeUnavailable      = "unavailable"
)

const genericInternalDetail = "internal error"

type FieldError struct {
	Location string `json:"location" doc:"Where the error occurred, for example body.email or query.limit"`
	Code     string `json:"code" doc:"Stable snake_case reason"`
	Message  string `json:"message" doc:"Human-readable explanation; never contains the submitted value"`
}

// Problem is an RFC 9457 problem document. Extensions are written as top-level members.
type Problem struct { //nolint:errname // named for RFC 9457 problem details, and Install and Mapper refer to it as Problem
	_          struct{}       `additionalProperties:"true"`
	Type       string         `json:"type,omitempty" doc:"A URI reference identifying the problem type"`
	Title      string         `json:"title" doc:"Short summary of the problem type"`
	Status     int            `json:"status" doc:"HTTP status code"`
	Detail     string         `json:"detail,omitempty" doc:"Explanation specific to this occurrence"`
	Code       string         `json:"code" doc:"Stable snake_case code clients can branch on"`
	RequestID  string         `json:"requestId,omitempty" doc:"Identifier to quote when reporting the problem"`
	Errors     []FieldError   `json:"errors,omitempty" doc:"One entry per failing field"`
	Extensions map[string]any `json:"-"`
}

func New(status int, code, detail string) *Problem {
	return &Problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, Detail: detail}
}

func Internal() *Problem {
	return New(http.StatusInternalServerError, CodeInternal, genericInternalDetail)
}

func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Detail
	}
	return p.Title
}

func (p *Problem) GetStatus() int { return p.Status }

// ContentType makes Huma answer with application/problem+json.
func (p *Problem) ContentType(ct string) string {
	if ct == "application/json" {
		return ContentType
	}
	return ct
}

// standardMembers cannot be set through Extensions, even when the standard member is empty.
var standardMembers = []string{"type", "title", "status", "detail", "code", "requestId", "errors"}

func (p *Problem) MarshalJSON() ([]byte, error) {
	type plain Problem
	if len(p.Extensions) == 0 {
		return json.Marshal((*plain)(p))
	}
	base, err := json.Marshal((*plain)(p))
	if err != nil {
		return nil, err
	}
	members := make(map[string]json.RawMessage, len(p.Extensions)+8)
	for k, v := range p.Extensions {
		if slices.Contains(standardMembers, k) {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		members[k] = raw
	}
	if err := json.Unmarshal(base, &members); err != nil {
		return nil, err
	}
	return json.Marshal(members)
}

type ctxKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// Write sends p, filling in the request id from the request context.
func Write(w http.ResponseWriter, r *http.Request, p *Problem) {
	out := *p
	if out.Status == 0 {
		out.Status = http.StatusInternalServerError
	}
	if out.RequestID == "" {
		out.RequestID = RequestID(r.Context())
	}
	body, err := json.Marshal(&out)
	if err != nil {
		body = []byte(`{"title":"Internal Server Error","status":500,"code":"internal"}`)
		out.Status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(out.Status)
	_, _ = w.Write(body) // a failed write means the client is gone
}
