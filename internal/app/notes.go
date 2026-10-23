//go:build !nonotes

package app

import (
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/modules/notes"
)

// notes is keel's example module; it needs tenancy, files, mail and xlsx.
func notesModules(w *wiring) []Module {
	return []Module{
		notes.New(notes.Deps{
			Realm: RealmTenant, BasePath: BasePath, DB: w.db, Audit: w.audit, Cursors: w.cursors, Jobs: w.queue,
			Mail: w.mail, Files: w.files, FeedRetention: w.cfg.Feed.TombstoneRetention,
		}),
	}
}

func init() {
	filePolicies[notes.AttachmentKind] = filePolicy{
		Policy: files.Policy{
			MaxBytes: 10 << 20, Types: []string{inspect.TypePDF, inspect.TypePNG, inspect.TypeJPEG, inspect.TypeText},
			Inspect: true, Visibility: files.Private,
		},
		Need: notes.PermWrite,
	}
	fileReaders[notes.OwnerType] = notes.ReadAttachment
}
