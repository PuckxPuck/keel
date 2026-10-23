package notes

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusArchived Status = "archived"
)

// Action is something a caller does to an existing note.
type Action string

const (
	ActionEdit    Action = "edit"
	ActionAttach  Action = "attach"
	ActionArchive Action = "archive"
	ActionDelete  Action = "delete"
)

const (
	maxTitle = 200
	maxBody  = 20000
)

var (
	ErrArchived        = errors.New("an archived note cannot be changed")
	ErrAlreadyArchived = errors.New("the note is already archived")
)

// FieldError is one broken rule on one input field.
type FieldError struct {
	Field   string
	Code    string
	Message string
}

// InvalidError lists every field that breaks a rule.
type InvalidError struct {
	Fields []FieldError
}

func (e *InvalidError) Error() string { return "the note is not valid" }

// transition is the status a note in status has after action, or why the action is refused. Archived
// notes are read-only: they can only be deleted.
func transition(status Status, action Action) (Status, error) {
	switch status {
	case StatusActive:
		if action == ActionArchive {
			return StatusArchived, nil
		}
		return status, nil
	case StatusArchived:
		switch action {
		case ActionDelete:
			return status, nil
		case ActionArchive:
			return status, ErrAlreadyArchived
		case ActionEdit, ActionAttach:
			return status, ErrArchived
		}
	}
	return status, fmt.Errorf("notes: unknown status %q", status)
}

// cleanTitle trims a title and refuses one that is blank or longer than maxTitle characters.
func cleanTitle(title string) (string, *FieldError) {
	title = strings.TrimSpace(title)
	switch {
	case title == "":
		return "", &FieldError{Field: "title", Code: "required", Message: "must not be blank"}
	case utf8.RuneCountInString(title) > maxTitle:
		return "", &FieldError{Field: "title", Code: "too_long", Message: "must be at most 200 characters"}
	}
	return title, nil
}

func checkBody(body string) *FieldError {
	if utf8.RuneCountInString(body) > maxBody {
		return &FieldError{Field: "body", Code: "too_long", Message: "must be at most 20000 characters"}
	}
	return nil
}

// invalid collects the fields that broke a rule into one error, or nil when none did.
func invalid(found ...*FieldError) error {
	var fields []FieldError
	for _, f := range found {
		if f != nil {
			fields = append(fields, *f)
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return &InvalidError{Fields: fields}
}

// wordCount is what the index job stores: words separated by white space.
func wordCount(body string) int {
	return len(strings.Fields(body))
}
