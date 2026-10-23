package notes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    Status
		action  Action
		want    Status
		wantErr error
	}{
		{"an active note is edited", StatusActive, ActionEdit, StatusActive, nil},
		{"an active note gets an attachment", StatusActive, ActionAttach, StatusActive, nil},
		{"an active note is archived", StatusActive, ActionArchive, StatusArchived, nil},
		{"an active note is deleted", StatusActive, ActionDelete, StatusActive, nil},
		{"an archived note cannot be edited", StatusArchived, ActionEdit, StatusArchived, ErrArchived},
		{"an archived note cannot get an attachment", StatusArchived, ActionAttach, StatusArchived, ErrArchived},
		{"an archived note is not archived twice", StatusArchived, ActionArchive, StatusArchived, ErrAlreadyArchived},
		{"an archived note can still be deleted", StatusArchived, ActionDelete, StatusArchived, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transition(tt.from, tt.action)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A draft reports every field that breaks a rule at once; lengths count characters, not bytes.
func TestDraftFields(t *testing.T) {
	tests := []struct {
		name, title, body string
		wantTitle         string
		wantFields        []string
	}{
		{"kept as typed", "Front desk", "Keys are in the drawer", "Front desk", nil},
		{"surrounding space trimmed", "  Front desk \t", "", "Front desk", nil},
		{"title at the limit in characters", strings.Repeat("é", maxTitle), "", strings.Repeat("é", maxTitle), nil},
		{"blank title refused", "   ", "", "", []string{"title"}},
		{"title over the limit refused", strings.Repeat("a", maxTitle+1), "", "", []string{"title"}},
		{"body at the limit in characters", "Log", strings.Repeat("é", maxBody), "Log", nil},
		{"both broken reported together", "", strings.Repeat("a", maxBody+1), "", []string{"title", "body"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, titleErr := cleanTitle(tt.title)
			err := invalid(titleErr, checkBody(tt.body))
			if tt.wantFields == nil {
				require.NoError(t, err)
				assert.Equal(t, tt.wantTitle, title)
				return
			}
			var refused *InvalidError
			require.ErrorAs(t, err, &refused)
			var fields []string
			for _, f := range refused.Fields {
				fields = append(fields, f.Field)
			}
			assert.Equal(t, tt.wantFields, fields)
		})
	}
}
