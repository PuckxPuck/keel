package migrate

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestMySQLLockName_FitsGetLock(t *testing.T) {
	long := strings.Repeat("d", 64)
	tests := []struct {
		name, key string
		hashed    bool
	}{
		{name: "short database name is used as is", key: "keel"},
		{name: "longest database name is hashed", key: long, hashed: true},
		{name: "multibyte names count characters", key: strings.Repeat("é", 58)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mysqlLockName(mysqlLockPrefix, tt.key)
			assert.LessOrEqual(t, utf8.RuneCountInString(got), mysqlMaxLockName)
			assert.Equal(t, !tt.hashed, got == mysqlLockPrefix+tt.key)
			assert.Equal(t, got, mysqlLockName(mysqlLockPrefix, tt.key), "lock and unlock use the same name")
		})
	}
	assert.NotEqual(t, mysqlLockName(mysqlLockPrefix, long), mysqlLockName(mysqlLockPrefix, long[1:]+"e"))
}
