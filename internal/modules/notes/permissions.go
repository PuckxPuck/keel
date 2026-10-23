package notes

import "github.com/PuckxPuck/keel/internal/kit/rbac"

const (
	PermRead    rbac.Code = "notes.read"
	PermWrite   rbac.Code = "notes.write"
	PermArchive rbac.Code = "notes.archive"
)

var permissions = []rbac.Perm{
	{Code: PermRead, Area: "Notes", Label: "See notes", Description: "List, open and export notes and download their attachments", APIGrantable: true},
	{Code: PermWrite, Area: "Notes", Label: "Change notes", Description: "Create, edit and delete notes and attach files", APIGrantable: true},
	{Code: PermArchive, Area: "Notes", Label: "Archive notes", Description: "Make notes read-only; their authors are told by email"},
}
