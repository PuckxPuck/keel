package logx

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"unicode"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

const (
	KeyRequestID = "request_id"
	KeyTraceID   = "trace_id"
	KeySpanID    = "span_id"
	KeyUserID    = "user_id"
	KeyTenantID  = "tenant_id"
	KeyClientIP  = "client_ip"
)

const redacted = "[redacted]"

type ctxKey int

const (
	attrsKey ctxKey = iota
	loggerKey
)

// Option adjusts New.
type Option func(*contextHandler)

// ContextAttrs adds the attributes fn finds in a record's context (trace and span ids) to every record.
func ContextAttrs(fn func(context.Context) []slog.Attr) Option {
	return func(h *contextHandler) { h.extra = fn }
}

func New(cfg config.Log, w io.Writer, opts ...Option) *slog.Logger {
	hopts := &slog.HandlerOptions{Level: cfg.Level, ReplaceAttr: redact}
	var inner slog.Handler
	if cfg.Format == config.LogText {
		inner = slog.NewTextHandler(w, hopts)
	} else {
		inner = slog.NewJSONHandler(w, hopts)
	}
	h := newContextHandler(inner)
	for _, o := range opts {
		o(h)
	}
	return slog.New(h)
}

// With adds attributes to every record logged with ctx; a key added again replaces the earlier value.
func With(ctx context.Context, attrs ...slog.Attr) context.Context {
	existing := ctxAttrs(ctx)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	for _, a := range attrs {
		replaced := false
		for i := range merged {
			if merged[i].Key == a.Key {
				merged[i], replaced = a, true
				break
			}
		}
		if !replaced {
			merged = append(merged, a)
		}
	}
	return context.WithValue(ctx, attrsKey, merged)
}

func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// From returns the context's logger (or the default one) bound to ctx, so plain Info calls carry the context attributes.
func From(ctx context.Context) *slog.Logger {
	base, ok := ctx.Value(loggerKey).(*slog.Logger)
	if !ok {
		base = slog.Default()
	}
	h := base.Handler()
	ch, ok := h.(*contextHandler)
	if !ok {
		ch = newContextHandler(h)
	}
	bound := *ch
	bound.bound = bound.withExtra(ctx, ctxAttrs(ctx))
	return slog.New(&bound)
}

func ctxAttrs(ctx context.Context) []slog.Attr {
	attrs, _ := ctx.Value(attrsKey).([]slog.Attr)
	return attrs
}

// contextHandler keeps the root handler and the WithAttrs/WithGroup calls
// separately so context attributes can be added before any group opens.
type contextHandler struct {
	root  slog.Handler
	ops   []handlerOp
	built slog.Handler
	bound []slog.Attr
	extra func(context.Context) []slog.Attr
}

// withExtra adds the extra attributes ctx carries to attrs, skipping keys attrs already has.
func (h *contextHandler) withExtra(ctx context.Context, attrs []slog.Attr) []slog.Attr {
	if h.extra == nil {
		return attrs
	}
	for _, a := range h.extra(ctx) {
		if !slices.ContainsFunc(attrs, func(b slog.Attr) bool { return b.Key == a.Key }) {
			attrs = append(slices.Clip(attrs), a)
		}
	}
	return attrs
}

type handlerOp struct {
	group string
	attrs []slog.Attr
}

func newContextHandler(root slog.Handler) *contextHandler {
	return &contextHandler{root: root, built: root}
}

func (h *contextHandler) replay(base slog.Handler) slog.Handler {
	for _, op := range h.ops {
		if op.attrs != nil {
			base = base.WithAttrs(op.attrs)
		} else {
			base = base.WithGroup(op.group)
		}
	}
	return base
}

func (h *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.root.Enabled(ctx, l)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := ctxAttrs(ctx)
	if len(attrs) == 0 {
		attrs = h.bound
	}
	attrs = h.withExtra(ctx, attrs)
	if len(attrs) == 0 {
		return h.built.Handle(ctx, r)
	}
	return h.replay(h.root.WithAttrs(attrs)).Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	next := *h
	next.ops = append(slices.Clone(h.ops), handlerOp{attrs: attrs})
	next.built = h.built.WithAttrs(attrs)
	return &next
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.ops = append(slices.Clone(h.ops), handlerOp{group: name})
	next.built = h.built.WithGroup(name)
	return &next
}

var sensitiveWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true, "secret": true,
	"token": true, "bearer": true, "authorization": true, "auth": true, "cookie": true,
	"session": true, "apikey": true, "otp": true, "pin": true, "jwt": true, "dsn": true,
	"credential": true, "signature": true, "email": true, "phone": true, "mobile": true,
}

var sensitivePairs = map[string]bool{
	"api key": true, "private key": true, "signing key": true, "database url": true,
}

// A trailing "code" is only sensitive after one of these, so status_code stays readable.
var codeQualifiers = map[string]bool{
	"otp": true, "totp": true, "recovery": true, "verification": true, "verify": true,
	"mfa": true, "sms": true, "backup": true, "reset": true, "invite": true,
	"activation": true, "confirmation": true, "security": true, "access": true,
	"login": true, "oauth": true, "auth": true, "pairing": true,
}

func redact(groups []string, a slog.Attr) slog.Attr {
	if isSensitive(a.Key) {
		return slog.String(a.Key, redacted)
	}
	for _, g := range groups {
		if isSensitive(g) {
			return slog.String(a.Key, redacted)
		}
	}
	return a
}

// Sensitive reports whether a key names a value logs redact; audit applies the same list to map keys.
func Sensitive(key string) bool { return isSensitive(key) }

func isSensitive(key string) bool {
	words := splitWords(key)
	for i, w := range words {
		if sensitiveWords[w] || sensitiveWords[strings.TrimSuffix(w, "s")] {
			return true
		}
		if i+1 < len(words) && sensitivePairs[w+" "+strings.TrimSuffix(words[i+1], "s")] {
			return true
		}
	}
	last := len(words) - 1
	if last < 0 || words[last] != "code" {
		return false
	}
	return last == 0 || codeQualifiers[words[last-1]]
}

// splitWords lower-cases and splits on non-alphanumerics, lower-to-upper
// changes, letter-digit changes, and the end of an acronym run (APIKey is api, key).
func splitWords(key string) []string {
	runes := []rune(key)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if i > 0 && len(cur) > 0 {
			prev := runes[i-1]
			switch {
			case unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)):
				flush()
			case unicode.IsDigit(r) != unicode.IsDigit(prev):
				flush()
			case unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]):
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}
