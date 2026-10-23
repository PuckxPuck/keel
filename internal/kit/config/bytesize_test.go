package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

func TestByteSize_Parse(t *testing.T) {
	tests := []struct {
		in      string
		want    config.ByteSize
		wantStr string
		wantErr bool
	}{
		{in: "1MiB", want: 1 << 20, wantStr: "1MiB"},
		{in: "20MiB", want: 20 << 20, wantStr: "20MiB"},
		{in: "2 GiB", want: 2 << 30, wantStr: "2GiB"},
		{in: "64kib", want: 64 << 10, wantStr: "64KiB"},
		{in: "1500", want: 1500, wantStr: "1500"},
		{in: "10B", want: 10, wantStr: "10"},
		{in: "0", want: 0, wantStr: "0"},
		{in: "", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "1.5MiB", wantErr: true},
		{in: "1MB", wantErr: true},
		{in: "9223372036854775807GiB", wantErr: true},
		{in: "9223372036854775808", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var got config.ByteSize
			err := got.UnmarshalText([]byte(tt.in))

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantStr, got.String())
		})
	}
}
