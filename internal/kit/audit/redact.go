package audit

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/dates"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/money"
)

const (
	redacted = "[redacted]"
	opaque   = "[opaque]"
)

// Redactable is a type with its own marshalling that says what the audit log may show of it.
// Other non-struct types with their own JSON or text marshalling are recorded as "[opaque]".
type Redactable interface {
	AuditValue() any
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
	redactable    = reflect.TypeFor[Redactable]()

	// safeMarshalers render whole: their marshalling shows nothing secret.
	safeMarshalers = map[reflect.Type]bool{
		reflect.TypeFor[time.Time]():     true,
		reflect.TypeFor[uuid.UUID]():     true,
		reflect.TypeFor[dates.Date]():    true,
		reflect.TypeFor[money.Amount]():  true,
		reflect.TypeFor[config.Secret](): true,
		reflect.TypeFor[json.Number]():   true,
	}
)

// keelIDs follows the module path, so typed ids keep matching after an app renames the module.
var keelIDs = reflect.TypeFor[ids.ID[struct{}]]().PkgPath()

// marshal renders v as canonical JSON with audit tags applied; nil stays nil.
func marshal(v any) (*string, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(scrub(reflect.ValueOf(v)))
	if err != nil {
		return nil, err
	}
	out, err := canonical(raw)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// scrub turns v into maps, slices and safe values. Struct fields are walked even when the struct has
// its own marshalling, so `audit:"redact"` and `audit:"-"` always apply.
func scrub(v reflect.Value) any {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		if v.Type().Implements(redactable) {
			return scrub(reflect.ValueOf(v.Interface().(Redactable).AuditValue()))
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil
	}
	t := v.Type()
	switch {
	case t.Implements(redactable):
		return scrub(reflect.ValueOf(v.Interface().(Redactable).AuditValue()))
	case safeMarshalers[t] || (t.PkgPath() == keelIDs && t.Kind() == reflect.Array):
		return v.Interface()
	case marshals(t) && (t.Kind() != reflect.Struct || !hasExportedField(t)):
		return opaque
	}
	switch v.Kind() { //nolint:exhaustive // every other kind is marshalled as it is
	case reflect.Struct:
		out := map[string]any{}
		scrubStruct(v, out)
		return out
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return v.Interface()
		}
		fallthrough
	case reflect.Array:
		out := make([]any, v.Len())
		for i := range v.Len() {
			out[i] = scrub(v.Index(i))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		out := make(map[string]any, v.Len())
		for it := v.MapRange(); it.Next(); {
			key := mapKey(it.Key())
			if logx.Sensitive(key) {
				out[key] = redacted
				continue
			}
			out[key] = scrub(it.Value())
		}
		return out
	case reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Complex64, reflect.Complex128:
		return opaque
	default:
		return v.Interface()
	}
}

func marshals(t reflect.Type) bool {
	pt := reflect.PointerTo(t)
	return t.Implements(jsonMarshaler) || t.Implements(textMarshaler) || pt.Implements(jsonMarshaler) || pt.Implements(textMarshaler)
}

func hasExportedField(t reflect.Type) bool {
	for i := range t.NumField() {
		if t.Field(i).IsExported() {
			return true
		}
	}
	return false
}

// mapKey stringifies a key the way encoding/json does, falling back to fmt for kinds it refuses.
func mapKey(k reflect.Value) string {
	if k.Kind() == reflect.String {
		return k.String()
	}
	if tm, ok := k.Interface().(encoding.TextMarshaler); ok {
		if b, err := tm.MarshalText(); err == nil {
			return string(b)
		}
	}
	switch k.Kind() { //nolint:exhaustive // the remaining kinds go through fmt
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(k.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(k.Uint(), 10)
	default:
		return fmt.Sprint(k.Interface())
	}
}

func scrubStruct(v reflect.Value, out map[string]any) {
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		tag := sf.Tag.Get("audit")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "-" && opts == "" {
			continue
		}
		fv := v.Field(i)
		if sf.Anonymous && name == "" && fv.Kind() == reflect.Struct {
			scrubStruct(fv, out)
			continue
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		if strings.Contains(opts, "omitempty") && fv.IsZero() {
			continue
		}
		if tag == "redact" {
			out[name] = redacted
			continue
		}
		out[name] = scrub(fv)
	}
}

// canonical re-encodes JSON with sorted keys and every number as an exact decimal without an exponent,
// so the text read back from jsonb or MySQL json (which reorder keys and rewrite numbers) hashes the
// same as the text written. Integers beyond 64 bits and decimals beyond float64 precision lose digits
// in MySQL json; marshal those as strings.
func canonical(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	v, err := exactNumbers(v)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func exactNumbers(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		return decimal(x)
	case map[string]any:
		for k, e := range x {
			n, err := exactNumbers(e)
			if err != nil {
				return nil, err
			}
			x[k] = n
		}
	case []any:
		for i, e := range x {
			n, err := exactNumbers(e)
			if err != nil {
				return nil, err
			}
			x[i] = n
		}
	}
	return v, nil
}

// decimal writes n exactly in positional notation with no trailing zeros: 1e21, 1E21 and
// 1000000000000000000000.0 all become 1000000000000000000000, and -0 becomes 0.
func decimal(n json.Number) (json.Number, error) {
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return "", fmt.Errorf("audit: number %q", n)
	}
	if r.IsInt() {
		return json.Number(r.Num().String()), nil
	}
	// A decimal literal's denominator is 2^a 5^b, so max(a, b) places are exact.
	d := new(big.Int).Set(r.Denom())
	places := 0
	for _, f := range []*big.Int{big.NewInt(2), big.NewInt(5)} {
		count := 0
		q, m := new(big.Int), new(big.Int)
		for {
			q.QuoRem(d, f, m)
			if m.Sign() != 0 {
				break
			}
			d.Set(q)
			count++
		}
		places = max(places, count)
	}
	s := strings.TrimRight(r.FloatString(places), "0")
	return json.Number(strings.TrimSuffix(s, ".")), nil
}
