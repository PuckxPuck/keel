package main

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPartRules(t *testing.T) {
	const mod = "module example.test/app\n"
	file := func(constraint, imp string) *fstest.MapFile {
		src := ""
		if constraint != "" {
			src = constraint + "\n\n"
		}
		return &fstest.MapFile{Data: []byte(src + "package app\n\nimport _ \"" + imp + "\"\n")}
	}
	tests := []struct {
		name   string
		path   string
		file   *fstest.MapFile
		breaks bool
	}{
		{"core file importing core kit", "internal/app/build.go", file("", "example.test/app/internal/kit/db"), false},
		{"core file importing an optional part", "internal/app/build.go", file("", "example.test/app/internal/kit/mail"), true},
		{"on file importing its own part", "internal/app/mail.go", file("//go:build !nomail", "example.test/app/internal/kit/mail"), false},
		{"on file importing another part", "internal/app/mail.go", file("//go:build !nomail", "example.test/app/internal/kit/files"), true},
		{"module part importing a part it requires", "internal/app/notes.go", file("//go:build !nonotes", "example.test/app/internal/kit/files/inspect"), false},
		{"off twin importing its part", "internal/app/mail_off.go", file("//go:build nomail", "example.test/app/internal/kit/mail"), true},
		{"test needing two parts", "internal/app/x_test.go", file("//go:build !notenancy && !noapikeys", "example.test/app/internal/kit/apikeys"), false},
		{"source needing two parts", "internal/app/x.go", file("//go:build !notenancy && !noapikeys", "fmt"), true},
		{"constraint that is not a part's", "internal/app/x.go", file("//go:build linux", "fmt"), true},
		{"an unknown part", "internal/app/x.go", file("//go:build !nosms", "fmt"), true},
		{"deploytest", "internal/app/x.go", file("//go:build deploytest", "fmt"), false},
		{"core kit importing an optional part", "internal/kit/audit/x.go", file("", "example.test/app/internal/kit/mail"), true},
		{"core kit test importing an optional part", "internal/kit/migrate/x_test.go", file("//go:build !notenancy", "example.test/app/internal/kit/tenancy"), true},
		{"optional kit importing another part", "internal/kit/docx/x_test.go", file("", "example.test/app/internal/kit/files/inspect"), true},
		{"optional kit importing its own part", "internal/kit/fileshttp/x.go", file("", "example.test/app/internal/kit/files"), false},
	}
	for _, tt := range tests {
		found, err := partRuleBreaks(fstest.MapFS{"go.mod": {Data: []byte(mod)}, tt.path: tt.file})
		require.NoError(t, err)
		assert.Equal(t, tt.breaks, len(found) > 0, "%s: %v", tt.name, found)
	}
}

func TestPartTagSets_JoinTheModulesThatNeedAPart(t *testing.T) {
	off := func(tag string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("//go:build " + tag + "\n\npackage app\n")}
	}
	sets, err := partTagSets(fstest.MapFS{
		"internal/app/mail_off.go":  off("nomail"),
		"internal/app/notes_off.go": off("nonotes"),
		"internal/app/pdf_off.go":   off("nopdf"),
	})
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"nomail", "nonotes"}, {"nonotes"}, {"nopdf"}, {"nomail", "nonotes", "nopdf"}}, sets)
	sets, err = partTagSets(fstest.MapFS{"internal/app/build.go": {Data: []byte("package app\n")}})
	require.NoError(t, err)
	assert.Empty(t, sets, "an app has no tags and vets nothing extra")
}
