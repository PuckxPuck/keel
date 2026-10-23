package dates_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/dates"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    dates.Date
		wantErr bool
	}{
		{in: "2026-10-22", want: dates.Date{Year: 2026, Month: time.October, Day: 22}},
		{in: "2024-02-29", want: dates.Date{Year: 2024, Month: time.February, Day: 29}},
		{in: "0001-01-01", want: dates.Date{Year: 1, Month: time.January, Day: 1}},
		{in: "9999-12-31", want: dates.Date{Year: 9999, Month: time.December, Day: 31}},
		{in: "2025-02-29", wantErr: true},
		{in: "2026-13-01", wantErr: true},
		{in: "2026-00-10", wantErr: true},
		{in: "2026-04-31", wantErr: true},
		{in: "0000-01-01", wantErr: true},
		{in: "2026-1-5", wantErr: true},
		{in: "2026/10/22", wantErr: true},
		{in: "20261022", wantErr: true},
		{in: "2026-10-22T00:00:00Z", wantErr: true},
		{in: " 2026-10-22", wantErr: true},
		{in: "+026-10-22", wantErr: true},
		{in: "2026-1a-22", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := dates.Parse(tt.in)

			if tt.wantErr {
				require.ErrorIs(t, err, dates.ErrInvalid)
				if tt.in != "" {
					assert.NotContains(t, err.Error(), tt.in, "errors never echo the input")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.in, got.String())
		})
	}
}

func TestAddDays(t *testing.T) {
	tests := []struct {
		from string
		n    int
		want string
	}{
		{"2026-10-22", 0, "2026-10-22"},
		{"2026-10-22", 10, "2026-11-01"},
		{"2026-10-22", -22, "2026-09-30"},
		{"2024-02-28", 1, "2024-02-29"},
		{"2025-02-28", 1, "2025-03-01"},
		{"2026-12-31", 1, "2027-01-01"},
		{"2026-01-01", -1, "2025-12-31"},
		{"2026-01-01", 365, "2027-01-01"},
	}
	for _, tt := range tests {
		t.Run(tt.from+" "+tt.want, func(t *testing.T) {
			assert.Equal(t, dates.MustParse(tt.want), dates.MustParse(tt.from).AddDays(tt.n))
		})
	}
}

func TestCompare_OrdersByYearMonthDay(t *testing.T) {
	a, b := dates.MustParse("2026-10-22"), dates.MustParse("2026-10-23")
	c := dates.MustParse("2027-01-01")

	assert.Equal(t, -1, a.Compare(b))
	assert.Equal(t, 1, b.Compare(a))
	assert.Equal(t, 0, a.Compare(dates.MustParse("2026-10-22")))
	assert.Equal(t, -1, b.Compare(c))
}

func TestIn_UsesTheLocationsMidnight(t *testing.T) {
	loc := time.FixedZone("UTC+5", 5*3600)

	got := dates.MustParse("2026-10-22").In(loc)

	assert.Equal(t, time.Date(2026, 10, 22, 0, 0, 0, 0, loc), got)
	assert.Equal(t, time.Date(2026, 10, 21, 19, 0, 0, 0, time.UTC), got.UTC())
}

func TestFromTime_UsesTheTimesOwnLocation(t *testing.T) {
	loc := time.FixedZone("x", 14*3600)
	instant := time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC)

	assert.Equal(t, dates.MustParse("2026-10-23"), dates.FromTime(instant.In(loc)))
	assert.Equal(t, dates.MustParse("2026-10-22"), dates.FromTime(instant))
}

func TestJSON(t *testing.T) {
	type payload struct {
		Due dates.Date  `json:"due"`
		End *dates.Date `json:"end"`
	}
	end := dates.MustParse("2026-12-31")

	raw, err := json.Marshal(payload{Due: dates.MustParse("2026-10-22"), End: &end})
	require.NoError(t, err)
	assert.JSONEq(t, `{"due":"2026-10-22","end":"2026-12-31"}`, string(raw))

	var back payload
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, dates.MustParse("2026-10-22"), back.Due)
	assert.Equal(t, &end, back.End)

	require.Error(t, json.Unmarshal([]byte(`{"due":"2026-02-30"}`), &back))
	require.Error(t, json.Unmarshal([]byte(`{"due":20261022}`), &back))
}

func TestInvalidDatesAreRefusedOnTheWayOut(t *testing.T) {
	tests := []struct {
		name string
		date dates.Date
	}{
		{"zero", dates.Date{}},
		{"month 13", dates.Date{Year: 2026, Month: 13, Day: 40}},
		{"day that does not exist", dates.Date{Year: 2026, Month: time.February, Day: 30}},
		{"past the last representable day", dates.MustParse("9999-12-31").AddDays(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, jsonErr := json.Marshal(tt.date)
			_, valueErr := tt.date.Value()

			require.ErrorIs(t, jsonErr, dates.ErrInvalid)
			require.ErrorIs(t, valueErr, dates.ErrInvalid)
		})
	}
}

func TestScanAndValue(t *testing.T) {
	want := dates.MustParse("2026-10-22")

	tests := []struct {
		name string
		src  any
	}{
		{"time at UTC midnight", time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)},
		{"string", "2026-10-22"},
		{"bytes", []byte("2026-10-22")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got dates.Date
			require.NoError(t, got.Scan(tt.src))
			assert.Equal(t, want, got)
		})
	}

	t.Run("rejects other types and bad strings", func(t *testing.T) {
		var got dates.Date
		require.Error(t, got.Scan(42))
		require.Error(t, got.Scan(nil))
		require.Error(t, got.Scan("not a date"))
		require.Error(t, got.Scan(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)))
	})
	t.Run("Value is the ISO string", func(t *testing.T) {
		v, err := want.Value()
		require.NoError(t, err)
		assert.Equal(t, "2026-10-22", v)
	})
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"2026-10-22", "0000-00-00", "9999-99-99", "2024-02-29", "", "----------", "２０２６-10-22", "2026-10-22\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := dates.Parse(s)
		if err != nil {
			return
		}
		assert.Equal(t, s, d.String(), "a parsed date renders back to the same text")
		again, err := dates.Parse(d.String())
		require.NoError(t, err)
		assert.Equal(t, d, again)
	})
}
