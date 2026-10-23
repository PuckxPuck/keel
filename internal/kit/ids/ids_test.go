package ids_test

import (
	"encoding/json"
	"testing"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type invoiceTag struct{}

type InvoiceID = ids.ID[invoiceTag]

const sample = "0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

func TestNew_IsTimeOrderedV7(t *testing.T) {
	prev := ids.New()
	assert.Equal(t, uuid.Version(7), prev.Version())
	for range 100 {
		next := ids.New()
		assert.Less(t, prev.String(), next.String(), "ids sort in creation order")
		prev = next
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "canonical lower case", in: sample},
		{name: "canonical upper case", in: "0198A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B"},
		{name: "empty", in: "", wantErr: true},
		{name: "no dashes", in: "0198a1b2c3d47e5f8a9b0c1d2e3f4a5b", wantErr: true},
		{name: "braces", in: "{" + sample + "}", wantErr: true},
		{name: "urn form", in: "urn:uuid:" + sample, wantErr: true},
		{name: "trailing space", in: sample + " ", wantErr: true},
		{name: "non hex", in: "0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5z", wantErr: true},
		{name: "all zero", in: "00000000-0000-0000-0000-000000000000", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ids.Parse[invoiceTag](tt.in)

			if tt.wantErr {
				require.ErrorIs(t, err, ids.ErrInvalid)
				if tt.in != "" {
					assert.NotContains(t, err.Error(), tt.in, "errors never echo the input")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, sample, id.String())
		})
	}
}

func TestJSON_IsAString(t *testing.T) {
	type payload struct {
		ID InvoiceID `json:"id"`
	}
	id := ids.MustParse[invoiceTag](sample)

	raw, err := json.Marshal(payload{ID: id})
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"`+sample+`"}`, string(raw))

	var back payload
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, id, back.ID)
	require.Error(t, json.Unmarshal([]byte(`{"id":"nope"}`), &back))

	_, err = json.Marshal(payload{})
	require.ErrorIs(t, err, ids.ErrInvalid, "an unset id never leaves the process")
	raw, err = json.Marshal(struct {
		Parent *InvoiceID `json:"parent"`
	}{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"parent":null}`, string(raw), "optional references are pointers")
}

func TestScanAndValue(t *testing.T) {
	want := ids.MustParse[invoiceTag](sample)
	raw := uuid.MustParse(sample)

	tests := []struct {
		name string
		src  any
	}{
		{"string", sample},
		{"text bytes", []byte(sample)},
		{"16 raw bytes", raw[:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got InvoiceID
			require.NoError(t, got.Scan(tt.src))
			assert.Equal(t, want, got)
		})
	}

	t.Run("NULL scans to the zero id but the zero id is never stored", func(t *testing.T) {
		got := want
		require.NoError(t, got.Scan(nil))
		assert.True(t, got.IsZero())

		_, err := InvoiceID{}.Value()
		require.ErrorIs(t, err, ids.ErrInvalid, "optional references are *ID, which database/sql stores as NULL")
	})
	t.Run("rejects other types, bad bytes and the all-zero uuid in every form", func(t *testing.T) {
		var got InvoiceID
		require.Error(t, got.Scan(42))
		require.Error(t, got.Scan([]byte{1, 2, 3}))
		require.ErrorIs(t, got.Scan(uuid.Nil[:]), ids.ErrInvalid)
		require.ErrorIs(t, got.Scan(uuid.Nil.String()), ids.ErrInvalid)
	})
	t.Run("Value is the text form", func(t *testing.T) {
		v, err := want.Value()
		require.NoError(t, err)
		assert.Equal(t, sample, v)
	})
}

func TestParam_BindsTheIDItself(t *testing.T) {
	id := ids.NewOf[invoiceTag]()
	_, args := postgres.SELECT(id.Param()).Sql()
	assert.Equal(t, []any{id}, args, "the driver calls Value, which refuses the zero id; Jet's UUID(id) would bind its string")
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{sample, "", "00000000-0000-0000-0000-000000000000", "{" + sample + "}", "urn:uuid:" + sample, "0198a1b2c3d47e5f8a9b0c1d2e3f4a5b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ids.Parse[invoiceTag](s)
		if err != nil {
			return
		}
		assert.Len(t, s, 36)
		assert.Equal(t, uuid.MustParse(s).String(), id.String())
		again, err := ids.Parse[invoiceTag](id.String())
		require.NoError(t, err)
		assert.Equal(t, id, again)
	})
}
