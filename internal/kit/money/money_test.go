package money_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/money"
)

func amt(t *testing.T, minor int64, code string) money.Amount {
	t.Helper()
	a, err := money.New(minor, code)
	require.NoError(t, err)
	return a
}

// A dependency bump that changed one of these would silently rescale stored amounts.
func TestExponents_ArePinned(t *testing.T) {
	tests := map[string]int32{"USD": 2, "EUR": 2, "JPY": 0, "KWD": 3, "BHD": 3, "MVR": 2}
	for code, digits := range tests {
		t.Run(code, func(t *testing.T) {
			d, err := amt(t, 1, code).Decimal()

			require.NoError(t, err)
			assert.Equal(t, decimal.New(1, -digits).String(), d.String())
		})
	}
}

func TestNew_ValidatesTheCurrency(t *testing.T) {
	for _, code := range []string{"", "usd", "US", "USDX", "XXY", " USD"} {
		t.Run("rejects "+code, func(t *testing.T) {
			_, err := money.New(100, code)
			require.ErrorIs(t, err, money.ErrCurrency)
			if code != "" {
				assert.NotContains(t, err.Error(), code, "errors never echo the input")
			}
		})
	}
	_, err := money.New(100, "USD")
	require.NoError(t, err)
}

func TestAddAndSub(t *testing.T) {
	usd := func(m int64) money.Amount { return amt(t, m, "USD") }

	tests := []struct {
		name    string
		op      func(a, b money.Amount) (money.Amount, error)
		a, b    money.Amount
		want    int64
		wantErr error
	}{
		{name: "add", op: money.Amount.Add, a: usd(1250), b: usd(75), want: 1325},
		{name: "add negative", op: money.Amount.Add, a: usd(100), b: usd(-250), want: -150},
		{name: "sub", op: money.Amount.Sub, a: usd(1250), b: usd(250), want: 1000},
		{name: "add to the maximum", op: money.Amount.Add, a: usd(math.MaxInt64 - 1), b: usd(1), want: math.MaxInt64},
		{name: "add overflow", op: money.Amount.Add, a: usd(math.MaxInt64), b: usd(1), wantErr: money.ErrOverflow},
		{name: "add underflow", op: money.Amount.Add, a: usd(math.MinInt64), b: usd(-1), wantErr: money.ErrOverflow},
		{name: "sub overflow", op: money.Amount.Sub, a: usd(math.MaxInt64), b: usd(-1), wantErr: money.ErrOverflow},
		{name: "sub of the minimum overflows", op: money.Amount.Sub, a: usd(0), b: usd(math.MinInt64), wantErr: money.ErrOverflow},
		{name: "sub of the minimum can land on the maximum", op: money.Amount.Sub, a: usd(-1), b: usd(math.MinInt64), want: math.MaxInt64},
		{name: "sub to the minimum", op: money.Amount.Sub, a: usd(math.MinInt64 + 1), b: usd(1), want: math.MinInt64},
		{name: "add with an unset currency", op: money.Amount.Add, a: money.Amount{Minor: 1}, b: money.Amount{Minor: 1}, wantErr: money.ErrCurrency},
		{name: "add mismatch", op: money.Amount.Add, a: usd(1), b: amt(t, 1, "EUR"), wantErr: money.ErrCurrencyMismatch},
		{name: "sub mismatch", op: money.Amount.Sub, a: usd(1), b: amt(t, 1, "JPY"), wantErr: money.ErrCurrencyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.op(tt.a, tt.b)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Minor)
			assert.Equal(t, tt.a.Currency, got.Currency)
		})
	}
}

func TestNeg_RefusesTheMinimum(t *testing.T) {
	got, err := amt(t, 250, "USD").Neg()
	require.NoError(t, err)
	assert.Equal(t, int64(-250), got.Minor)

	_, err = amt(t, math.MinInt64, "USD").Neg()
	require.ErrorIs(t, err, money.ErrOverflow)
}

func TestAllocate(t *testing.T) {
	tests := []struct {
		name    string
		minor   int64
		code    string
		weights []int
		want    []int64
	}{
		{name: "three way split of 1.00 gives the extra cent to the first", minor: 100, code: "USD", weights: []int{1, 1, 1}, want: []int64{34, 33, 33}},
		{name: "five percent split of 0.05", minor: 5, code: "USD", weights: []int{3, 7}, want: []int64{2, 3}},
		{name: "largest remainder wins, not the first", minor: 10, code: "USD", weights: []int{1, 1, 8}, want: []int64{1, 1, 8}},
		{name: "remainders decide the extra units", minor: 7, code: "USD", weights: []int{1, 2, 4}, want: []int64{1, 2, 4}},
		{name: "ties keep weight order", minor: 2, code: "USD", weights: []int{1, 1, 1}, want: []int64{1, 1, 0}},
		{name: "zero weights get nothing", minor: 100, code: "USD", weights: []int{0, 1, 0, 1}, want: []int64{0, 50, 0, 50}},
		{name: "negative amount keeps the sum and the sign", minor: -100, code: "USD", weights: []int{1, 1, 1}, want: []int64{-34, -33, -33}},
		{name: "zero amount", minor: 0, code: "USD", weights: []int{1, 2}, want: []int64{0, 0}},
		{name: "single weight takes everything", minor: 999, code: "USD", weights: []int{5}, want: []int64{999}},
		{name: "kuwaiti dinar uses its 3 decimals", minor: 1000, code: "KWD", weights: []int{1, 1, 1}, want: []int64{334, 333, 333}},
		{name: "yen has no minor unit", minor: 100, code: "JPY", weights: []int{1, 1, 1}, want: []int64{34, 33, 33}},
		{name: "huge weights do not overflow", minor: math.MaxInt64, code: "USD", weights: []int{math.MaxInt, math.MaxInt}, want: []int64{math.MaxInt64/2 + 1, math.MaxInt64 / 2}},
		{name: "the minimum amount", minor: math.MinInt64, code: "USD", weights: []int{1}, want: []int64{math.MinInt64}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := amt(t, tt.minor, tt.code).Allocate(tt.weights...)

			require.NoError(t, err)
			var got []int64
			var sum int64
			for _, p := range parts {
				got = append(got, p.Minor)
				sum += p.Minor
				assert.Equal(t, tt.code, p.Currency)
			}
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.minor, sum, "no minor unit is lost")
		})
	}
}

func TestAllocate_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		weights []int
	}{
		{"no weights", nil},
		{"all zero", []int{0, 0}},
		{"negative weight", []int{1, -1}},
	}
	_, err := money.Amount{Minor: 100}.Allocate(1)
	require.ErrorIs(t, err, money.ErrCurrency)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := amt(t, 100, "USD").Allocate(tt.weights...)
			require.ErrorIs(t, err, money.ErrAllocation)
		})
	}
}

func TestFromDecimal(t *testing.T) {
	tests := []struct {
		in   string
		code string
		mode money.RoundingMode
		want int64
	}{
		{"12.345", "USD", money.HalfEven, 1234},
		{"12.355", "USD", money.HalfEven, 1236},
		{"12.345", "USD", money.HalfUp, 1235},
		{"12.341", "USD", money.Up, 1235},
		{"12.349", "USD", money.Down, 1234},
		{"-12.345", "USD", money.HalfEven, -1234},
		{"-12.345", "USD", money.HalfUp, -1235},
		{"-12.341", "USD", money.Up, -1235},
		{"-12.349", "USD", money.Down, -1234},
		{"12.30", "USD", money.Up, 1230},
		{"0.0004", "USD", money.Up, 1},
		{"0.0004", "USD", money.HalfEven, 0},
		{"1.2345", "KWD", money.HalfEven, 1234},
		{"1.2346", "KWD", money.HalfEven, 1235},
		{"1.0005", "KWD", money.HalfUp, 1001},
		{"1234.5", "JPY", money.HalfEven, 1234},
		{"1234.5", "JPY", money.HalfUp, 1235},
		{"1234.1", "JPY", money.Up, 1235},
		{"1500000", "JPY", money.Down, 1500000},
	}
	for _, tt := range tests {
		t.Run(tt.in+" "+tt.code, func(t *testing.T) {
			got, err := money.FromDecimal(decimal.RequireFromString(tt.in), tt.code, tt.mode)

			require.NoError(t, err)
			assert.Equal(t, money.Amount{Minor: tt.want, Currency: tt.code}, got)
		})
	}
}

func TestFromDecimal_Refusals(t *testing.T) {
	_, err := money.FromDecimal(decimal.RequireFromString("1"), "ZZZ", money.HalfEven)
	require.ErrorIs(t, err, money.ErrCurrency)

	_, err = money.FromDecimal(decimal.RequireFromString("1"), "USD", 0)
	require.ErrorIs(t, err, money.ErrRounding)

	_, err = money.FromDecimal(decimal.RequireFromString("92233720368547758.08"), "USD", money.HalfEven)
	require.ErrorIs(t, err, money.ErrOverflow)
}

func TestDecimalRoundTrip(t *testing.T) {
	for _, code := range []string{"USD", "KWD", "JPY"} {
		t.Run(code, func(t *testing.T) {
			a := amt(t, 123456, code)

			d, err := a.Decimal()
			require.NoError(t, err)
			back, err := money.FromDecimal(d, code, money.HalfEven)

			require.NoError(t, err)
			assert.Equal(t, a, back)
		})
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		amount money.Amount
		locale string
		want   string
	}{
		{money.Amount{Minor: 123456, Currency: "USD"}, "en-US", "$1,234.56"},
		{money.Amount{Minor: -5, Currency: "USD"}, "en-US", "-$0.05"},
		{money.Amount{Minor: 123456, Currency: "EUR"}, "de-DE", "1.234,56 €"},
		{money.Amount{Minor: 1234567, Currency: "JPY"}, "ja-JP", "￥1,234,567"},
		{money.Amount{Minor: 1234, Currency: "KWD"}, "en", "KWD\u00a01.234"},
	}
	for _, tt := range tests {
		t.Run(tt.amount.Currency+" "+tt.locale, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.amount.Format(tt.locale))
		})
	}
	assert.Equal(t, "5 XXX", money.Amount{Minor: 5, Currency: "XXX"}.Format("en"), "unknown currencies fall back to a plain rendering")
}

func TestJSON(t *testing.T) {
	raw, err := json.Marshal(amt(t, 1250, "USD"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"amount":1250,"currency":"USD"}`, string(raw))

	_, err = json.Marshal(money.Amount{})
	require.ErrorIs(t, err, money.ErrCurrency, "the zero Amount cannot be written out")

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "valid", in: `{"amount":1250,"currency":"USD"}`},
		{name: "negative", in: `{"amount":-1,"currency":"JPY"}`},
		{name: "fractional amount", in: `{"amount":12.5,"currency":"USD"}`, wantErr: true},
		{name: "amount as string", in: `{"amount":"1250","currency":"USD"}`, wantErr: true},
		{name: "exponent form", in: `{"amount":1e3,"currency":"USD"}`, wantErr: true},
		{name: "beyond int64", in: `{"amount":9223372036854775808,"currency":"USD"}`, wantErr: true},
		{name: "missing currency", in: `{"amount":1}`, wantErr: true},
		{name: "missing amount", in: `{"currency":"USD"}`, wantErr: true},
		{name: "unknown currency", in: `{"amount":1,"currency":"ZZZ"}`, wantErr: true},
		{name: "lower case currency", in: `{"amount":1,"currency":"usd"}`, wantErr: true},
		{name: "unknown field", in: `{"amount":1,"currency":"USD","extra":true}`, wantErr: true},
		{name: "null", in: `null`, wantErr: true},
		{name: "array", in: `[1,"USD"]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a money.Amount
			err := json.Unmarshal([]byte(tt.in), &a)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func FuzzUnmarshalJSON(f *testing.F) {
	for _, seed := range []string{`{"amount":1250,"currency":"USD"}`, `{}`, `null`, `{"amount":1e400,"currency":"USD"}`, `{"amount":1,"currency":"USD","x":1}`, `[]`, `{"amount":-9223372036854775808,"currency":"KWD"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a money.Amount
		if err := json.Unmarshal(data, &a); err != nil {
			return
		}
		_, err := money.New(a.Minor, a.Currency)
		require.NoError(t, err, "a decoded amount always has a valid currency")

		raw, err := json.Marshal(a)
		require.NoError(t, err)
		var back money.Amount
		require.NoError(t, json.Unmarshal(raw, &back))
		assert.Equal(t, a, back)
	})
}
