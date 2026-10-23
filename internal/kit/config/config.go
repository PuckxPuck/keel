package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/caarlos0/env/v11"
)

type Validator interface {
	Validate(prod bool) error
}

// LoadFrom reads prefix-qualified variables from environ (os.Environ form) and validates every part.
func LoadFrom[T any](prefix string, environ []string) (T, error) {
	var zero T
	vars := env.ToMap(environ)

	if err := readFileVars[T](prefix, vars); err != nil {
		return zero, err
	}

	cfg, err := env.ParseAsWithOptions[T](env.Options{Prefix: prefix, Environment: vars})
	if err != nil {
		return zero, fmt.Errorf("parse config: %w", err)
	}

	root := reflect.ValueOf(&cfg).Elem()
	prod, err := isProd(root)
	if err != nil {
		return zero, err
	}
	if err := validate(root, "", prod); err != nil {
		return zero, err
	}
	return cfg, nil
}

func readFileVars[T any](prefix string, vars map[string]string) error {
	var errs []error
	root := reflect.New(reflect.TypeFor[T]()).Elem()
	walk(root, prefix, func(key string, _ reflect.Value) {
		fileVar := key + "_FILE"
		path := vars[fileVar]
		if path == "" {
			return
		}
		if vars[key] != "" {
			errs = append(errs, fmt.Errorf("set one of %s or %s", key, fileVar))
			return
		}
		raw, err := readCapped(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", fileVar, err))
			return
		}
		vars[key] = strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
	})
	return errors.Join(errs...)
}

const maxFileVarBytes = 64 << 10

func readCapped(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is an operator-set variable by design
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFileVarBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxFileVarBytes {
		return "", fmt.Errorf("larger than %d bytes", maxFileVarBytes)
	}
	return string(raw), nil
}

func isProd(root reflect.Value) (bool, error) {
	var found, prod bool
	var visit func(v reflect.Value)
	visit = func(v reflect.Value) {
		for i := range v.NumField() {
			f := v.Field(i)
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if e, ok := f.Interface().(Env); ok && !found {
				found, prod = true, e.IsProd()
				continue
			}
			if f.Kind() == reflect.Struct {
				visit(f)
			}
		}
	}
	visit(root)
	if !found {
		return false, errors.New("config struct needs a config.Env field")
	}
	return prod, nil
}

func validate(v reflect.Value, path string, prod bool) error {
	var errs []error
	if v.CanAddr() {
		if val, ok := v.Addr().Interface().(Validator); ok {
			if err := val.Validate(prod); err != nil {
				errs = append(errs, labelled(path, err))
			}
		}
	}
	if v.Kind() != reflect.Struct {
		return errors.Join(errs...)
	}
	t := v.Type()
	for i := range v.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		child := sf.Name
		if path != "" {
			child = path + "." + sf.Name
		}
		if err := validate(v.Field(i), child, prod); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func labelled(path string, err error) error {
	if path == "" {
		return err
	}
	return fmt.Errorf("%s: %w", path, err)
}

// walk visits every env-tagged field with its full variable name. Struct fields
// without an env tag are entered with their envPrefix, as caarlos0/env does.
func walk(v reflect.Value, prefix string, fn func(key string, v reflect.Value)) {
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		fv := v.Field(i)
		if tag, ok := sf.Tag.Lookup("env"); ok {
			if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
				fn(prefix+name, fv)
			}
			continue
		}
		if fv.Kind() == reflect.Struct {
			walk(fv, prefix+sf.Tag.Get("envPrefix"), fn)
		}
	}
}
