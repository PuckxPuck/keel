package password

import (
	_ "embed"
	"errors"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

// common.txt is the first 5,000 distinct entries of 8 to 128 printable ASCII characters, lower-cased,
// from SecLists' xato-net-10-million-passwords-100000.txt (MIT); see docs/stack.md.
//
//go:embed common.txt
var commonList string

var common = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 5000)
	for line := range strings.Lines(commonList) {
		if w := strings.TrimSpace(line); w != "" {
			set[w] = struct{}{}
		}
	}
	return set
})

// Lengths per NIST SP 800-63B-4: 15 characters when the password is the only factor, 8 when the realm
// requires a second one.
const (
	MinSingleFactor = 15
	MinWithMFA      = 8
)

// Policy is what a new password must meet. There are no composition rules.
type Policy struct {
	MinLength int
}

const (
	ReasonTooShort = "too_short"
	ReasonTooLong  = "too_long"
	ReasonCommon   = "common"
	ReasonInvalid  = "invalid"
)

// PolicyError lists why a new password was refused.
type PolicyError struct {
	Reasons []string
}

func (e *PolicyError) Error() string {
	return "password does not meet the policy: " + strings.Join(e.Reasons, ", ")
}

// Check refuses a password shorter than MinLength characters, longer than MaxChars characters or
// MaxBytes bytes, or on the common-password list. Length and the list apply to the NFKC form that is
// hashed; the list compares case-insensitively.
func (p Policy) Check(plain string) error {
	if !utf8.ValidString(plain) {
		return &PolicyError{Reasons: []string{ReasonInvalid}}
	}
	normalised := norm.NFKC.String(plain)
	var reasons []string
	if utf8.RuneCountInString(normalised) < max(p.MinLength, MinWithMFA) {
		reasons = append(reasons, ReasonTooShort)
	}
	if TooLong(plain) {
		reasons = append(reasons, ReasonTooLong)
	}
	if _, found := common()[strings.ToLower(normalised)]; found {
		reasons = append(reasons, ReasonCommon)
	}
	if len(reasons) > 0 {
		return &PolicyError{Reasons: reasons}
	}
	return nil
}

var messages = map[string]string{
	ReasonTooShort: "is shorter than the minimum length",
	ReasonTooLong:  "is longer than 128 characters",
	ReasonCommon:   "is too common; choose another",
	ReasonInvalid:  "is not valid text",
}

// Mapper answers a PolicyError with 422 validation_failed on body.password, a throttled sign-in with
// 429, and bad credentials with 401 invalid_credentials.
func Mapper(err error) (*problem.Problem, bool) {
	var pe *PolicyError
	switch {
	case errors.As(err, &pe):
		p := problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, "the request failed validation")
		for _, r := range pe.Reasons {
			p.Errors = append(p.Errors, problem.FieldError{Location: "body.password", Code: r, Message: messages[r]})
		}
		return p, true
	case errors.Is(err, ErrInvalidCredentials):
		return problem.New(http.StatusUnauthorized, CodeInvalidCredentials, "the email or password is not right"), true
	}
	return nil, false
}
