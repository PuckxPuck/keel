package problem

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/validation"

	"github.com/PuckxPuck/keel/internal/kit/logx"
)

// Mapper turns a domain error into a problem; ok is false when it does not recognise err.
type Mapper func(error) (p *Problem, ok bool)

var (
	mappers     atomic.Pointer[[]Mapper]
	mappersMu   sync.Mutex
	installOnce sync.Once
)

// Install replaces Huma's error constructors so every error leaves as a Problem, and adds m
// to the mappers, which are tried in the order they were added. Call it before registering operations.
func Install(m ...Mapper) {
	mappersMu.Lock()
	var all []Mapper
	if current := mappers.Load(); current != nil {
		all = slices.Clone(*current)
	}
	all = append(all, m...)
	mappers.Store(&all)
	mappersMu.Unlock()

	installOnce.Do(func() {
		huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
			return build(nil, status, msg, errs)
		}
		huma.NewErrorWithContext = func(ctx huma.Context, status int, msg string, errs ...error) huma.StatusError {
			return build(ctx, status, msg, errs)
		}
	})
}

// Transformer stamps the request id on problems Huma writes.
func Transformer(ctx huma.Context, _ string, v any) (any, error) {
	p, ok := v.(*Problem)
	if !ok || p.RequestID != "" {
		return v, nil
	}
	out := *p
	out.RequestID = RequestID(ctx.Context())
	return &out, nil
}

func build(ctx huma.Context, status int, msg string, errs []error) *Problem {
	for _, err := range errs {
		if err == nil {
			continue
		}
		if p, ok := mapError(err); ok {
			return p
		}
	}

	var tooLarge *http.MaxBytesError
	for _, err := range errs {
		if errors.As(err, &tooLarge) {
			return New(http.StatusRequestEntityTooLarge, CodeTooLarge, "request body is too large")
		}
	}

	if status >= http.StatusInternalServerError && status != http.StatusServiceUnavailable {
		logCause(ctx, errs)
		return Internal()
	}

	p := New(status, codeForStatus(status), msg)
	switch status {
	case http.StatusRequestEntityTooLarge:
		p.Detail = "request body is too large"
	case http.StatusUnprocessableEntity:
		p.Code, p.Detail = CodeValidationFailed, "the request failed validation"
	}
	for _, err := range errs {
		var detail huma.ErrorDetailer
		if errors.As(err, &detail) {
			p.Errors = append(p.Errors, fieldError(detail.ErrorDetail()))
		}
	}
	if status == http.StatusBadRequest && len(p.Errors) == 1 && p.Errors[0].Location == "body" {
		p.Code, p.Detail, p.Errors = CodeInvalidJSON, "the request body is not valid JSON", nil
	}
	return p
}

func mapError(err error) (*Problem, bool) {
	var p *Problem
	if errors.As(err, &p) {
		return p, true
	}
	if list := mappers.Load(); list != nil {
		for _, m := range *list {
			if p, ok := m(err); ok {
				return p, true
			}
		}
	}
	return nil, false
}

func logCause(ctx huma.Context, errs []error) {
	if ctx == nil {
		return
	}
	for _, err := range errs {
		logx.From(ctx.Context()).Error("unhandled error", "error", err)
	}
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusNotAcceptable:
		return "not_acceptable"
	case http.StatusRequestTimeout:
		return "request_timeout"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return CodeTooLarge
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusUnprocessableEntity:
		return CodeValidationFailed
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	}
	return strings.ReplaceAll(strings.ToLower(http.StatusText(status)), " ", "_")
}

type rule struct {
	prefix, code, message string
}

// Huma's messages can embed the submitted value (format and parse errors), so
// every field error is rebuilt from the matched rule and the original is dropped.
var rules = buildRules()

func buildRules() []rule {
	def := func(template, code, message string) rule {
		prefix, _, _ := strings.Cut(template, "%")
		return rule{prefix: prefix, code: code, message: message}
	}
	list := []rule{
		def(validation.MsgUnexpectedProperty, "unknown_field", "is not allowed"),
		def(validation.MsgExpectedRequiredProperty, "required", "is required"),
		def(validation.MsgExpectedDependentRequiredProperty, "required", "is required"),
		def(validation.MsgExpectedBoolean, "type", "has the wrong type"),
		def(validation.MsgExpectedNumber, "type", "has the wrong type"),
		def(validation.MsgExpectedInteger, "type", "has the wrong type"),
		def(validation.MsgExpectedString, "type", "has the wrong type"),
		def(validation.MsgExpectedArray, "type", "has the wrong type"),
		def(validation.MsgExpectedObject, "type", "has the wrong type"),
		def(validation.MsgExpectedRFC5322Email, "format", "must be an email address"),
		def(validation.MsgExpectedRFC5322EmailBare, "format", "must be an email address"),
		def(validation.MsgExpectedRFC3339DateTime, "format", "must be an RFC 3339 date and time"),
		def(validation.MsgExpectedRFC3339Date, "format", "must be a date as YYYY-MM-DD"),
		def(validation.MsgExpectedRFC3339Time, "format", "must be an RFC 3339 time"),
		def(validation.MsgExpectedRFC1123DateTime, "format", "must be an RFC 1123 date and time"),
		def(validation.MsgExpectedRFC4122UUID, "format", "must be a UUID"),
		def(validation.MsgExpectedRFC3986URI, "format", "must be a URI"),
		def(validation.MsgExpectedRFC3986AbsoluteURI, "format", "must be an absolute URI"),
		def(validation.MsgExpectedRFC5890Hostname, "format", "must be a hostname"),
		def(validation.MsgExpectedRFC2673IPv4, "format", "must be an IPv4 address"),
		def(validation.MsgExpectedRFC2373IPv6, "format", "must be an IPv6 address"),
		def(validation.MsgExpectedRFCIPAddr, "format", "must be an IP address"),
		def(validation.MsgExpectedRFC6570URITemplate, "format", "has an invalid format"),
		def(validation.MsgExpectedRFC6901JSONPointer, "format", "has an invalid format"),
		def(validation.MsgExpectedRFC6901RelativeJSONPointer, "format", "has an invalid format"),
		def(validation.MsgExpectedBase64String, "format", "must be base64 encoded"),
		def(validation.MsgExpectedDuration, "format", "must be a duration"),
		def(validation.MsgExpectedRegexp, "pattern", "does not match the required pattern"),
		def(validation.MsgExpectedBePattern, "pattern", "does not match the required pattern"),
		def(validation.MsgExpectedMatchPattern, "pattern", "does not match the required pattern"),
		def(validation.MsgExpectedOneOf, "enum", "must be one of the allowed values"),
		def(validation.MsgExpectedConst, "enum", "must be one of the allowed values"),
		def(validation.MsgExpectedMinimumNumber, "minimum", "is too small"),
		def(validation.MsgExpectedExclusiveMinimumNumber, "minimum", "is too small"),
		def(validation.MsgExpectedMaximumNumber, "maximum", "is too large"),
		def(validation.MsgExpectedExclusiveMaximumNumber, "maximum", "is too large"),
		def(validation.MsgExpectedNumberBeMultipleOf, "multiple_of", "is not a valid multiple"),
		def(validation.MsgExpectedMinLength, "min_length", "is too short"),
		def(validation.MsgExpectedMaxLength, "max_length", "is too long"),
		def(validation.MsgExpectedMinItems, "min_items", "has too few items"),
		def(validation.MsgExpectedMaxItems, "max_items", "has too many items"),
		def(validation.MsgExpectedMinProperties, "min_properties", "has too few properties"),
		def(validation.MsgExpectedMaxProperties, "max_properties", "has too many properties"),
		def(validation.MsgExpectedArrayItemsUnique, "unique", "must not contain duplicates"),
	}
	slices.SortStableFunc(list, func(a, b rule) int { return len(b.prefix) - len(a.prefix) })
	return list
}

func fieldError(d *huma.ErrorDetail) FieldError {
	location := d.Location
	for _, r := range rules {
		if !strings.HasPrefix(d.Message, r.prefix) {
			continue
		}
		switch r.code {
		case "required":
			location = joinLocation(location, requiredName(d.Message))
		case "unknown_field":
			location = capLocation(location)
		}
		return FieldError{Location: location, Code: r.code, Message: r.message}
	}
	return FieldError{Location: location, Code: "invalid", Message: "is invalid"}
}

// maxEchoedLocation bounds an unknown property name echoed back from the request.
const maxEchoedLocation = 64

func capLocation(location string) string {
	if len(location) <= maxEchoedLocation {
		return location
	}
	return strings.ToValidUTF8(location[:maxEchoedLocation], "")
}

func requiredName(message string) string {
	const prefix, suffix = "expected required property ", " to be present"
	name, ok := strings.CutPrefix(message, prefix)
	if !ok {
		return ""
	}
	return strings.TrimSuffix(name, suffix)
}

func joinLocation(base, name string) string {
	switch {
	case name == "":
		return base
	case base == "":
		return name
	}
	return base + "." + name
}
