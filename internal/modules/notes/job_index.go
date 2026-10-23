package notes

import (
	"context"

	"github.com/PuckxPuck/keel/internal/kit/jobs"
)

const KindIndex = "notes.index"

// IndexPayload is what a KindIndex job carries: ids, not records, and no personal data.
type IndexPayload struct {
	NoteID ID `json:"noteId"`
}

// runIndex counts the words of the note's body; every change to the body queues one.
func (m *Module) runIndex(ctx context.Context, _ jobs.Job, p IndexPayload) error {
	return m.svc.index(ctx, p.NoteID)
}
