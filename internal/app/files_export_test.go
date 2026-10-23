//go:build !nofiles

package app

import (
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// MountTestFileKind adds an upload kind until restore runs; Build must come after it.
func MountTestFileKind(kind string, policy files.Policy, need rbac.Code) (restore func()) {
	filePolicies[kind] = filePolicy{Policy: policy, Need: need}
	return func() { delete(filePolicies, kind) }
}
