package config

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

const redacted = "[redacted]"

type Secret string

func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

func (s Secret) Reveal() string { return string(s) }

const minStrongBytes = 32

// exampleValues are the placeholders shipped in .env.example and compose files.
var exampleValues = []string{
	"changeme", "change-me", "change_me", "replace-me", "replace_me", "example", "secret", "password",
	"keel-local", "keel-owner-local", "keel-app-local", "keel-operator-local",
}

// RequireStrong refuses, in production, a secret that is too short or still an example value.
func RequireStrong(name string, s Secret, prod bool) error {
	if !prod {
		return nil
	}
	v := s.Reveal()
	if slices.Contains(exampleValues, strings.ToLower(v)) {
		return fmt.Errorf("%s still has its example value", name)
	}
	if len(v) < minStrongBytes {
		return errors.New(name + " must be at least 32 bytes in production")
	}
	return nil
}
