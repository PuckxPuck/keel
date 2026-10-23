package config

import (
	"fmt"
	"reflect"
	"strings"
)

type Entry struct {
	Key   string
	Value string
}

// Describe lists every env-backed field in declaration order; secrets render redacted.
func Describe[T any](prefix string, cfg T) []Entry {
	var entries []Entry
	walk(reflect.ValueOf(&cfg).Elem(), prefix, func(key string, v reflect.Value) {
		entries = append(entries, Entry{Key: key, Value: render(v)})
	})
	return entries
}

func render(v reflect.Value) string {
	if v.Kind() == reflect.Slice {
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = fmt.Sprint(v.Index(i).Interface())
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(v.Interface())
}
