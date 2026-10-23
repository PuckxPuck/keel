package testdb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpired_DropsOnlyWhatTestdbMade(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	tests := []struct {
		name string
		db   string
		want bool
	}{
		{name: "old test database", db: testName("keel", old), want: true},
		{name: "old template of another hash", db: templateName("keel", "0123456789ab", old), want: true},
		{name: "recent test database", db: testName("keel", now.Add(-time.Hour))},
		{name: "current template however old", db: templateName("keel", "aaaaaaaaaaaa", old)},
		{name: "another prefix", db: testName("keelx", old)},
		{name: "app database that looks dated", db: "keel_tenants_20250101000000"},
		{name: "backup with the marker but not the shape", db: "keel_testdb_backup_20250101000000"},
		{name: "extra suffix", db: testName("keel", old) + "_copy"},
		{name: "impossible stamp", db: "keel_testdb_20251399000000_0123abcd"},
		{name: "upper-case hex is not ours", db: "keel_testdb_20250101000000_0123ABCD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, expired(tt.db, "keel", "aaaaaaaaaaaa", now))
		})
	}
}
