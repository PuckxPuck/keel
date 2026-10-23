// Package users holds the global user identity: email, name and status. Sign-in data lives with auth.
package users

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type userTag struct{}

type ID = ids.ID[userTag]

type Status string

const (
	Active   Status = "active"
	Disabled Status = "disabled"
)

func (s Status) Valid() bool {
	switch s {
	case Active, Disabled:
		return true
	}
	return false
}

type User struct {
	ID     ID     `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	// EmailVerifiedAt is when the user first proved the address (an invite or a verification link).
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	Version         int        `json:"version"`
}

var (
	ErrNotFound     = errors.New("user not found")
	ErrEmailTaken   = errors.New("email is already in use")
	ErrInvalidEmail = errors.New("email is not a valid address")
	ErrInvalidName  = errors.New("name must be at most 200 characters")
)

const (
	maxEmail = 254
	maxName  = 200
)

// NormaliseEmail trims, lower-cases and NFC-normalises an address and checks its basic shape; delivery
// proves the rest. Stored addresses are normalised, so lookups compare exactly on both engines.
func NormaliseEmail(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", ErrInvalidEmail
	}
	email := norm.NFC.String(strings.ToLower(strings.TrimSpace(raw)))
	local, domain, ok := strings.Cut(email, "@")
	switch {
	case !ok || local == "" || domain == "" || strings.Contains(domain, "@"):
		return "", ErrInvalidEmail
	case utf8.RuneCountInString(email) > maxEmail:
		return "", ErrInvalidEmail
	case strings.IndexFunc(email, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return "", ErrInvalidEmail
	case !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, "."):
		return "", ErrInvalidEmail
	}
	return email, nil
}

// Mapper turns the package's errors into problems.
func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, "user not found"), true
	case errors.Is(err, ErrEmailTaken):
		return problem.New(http.StatusConflict, "email_taken", "email is already in use"), true
	case errors.Is(err, ErrInvalidEmail), errors.Is(err, ErrInvalidName):
		return problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, err.Error()), true
	}
	return nil, false
}
