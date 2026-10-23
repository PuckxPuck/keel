package money

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/bojanz/currency"
	"github.com/shopspring/decimal"
)

var (
	ErrCurrency         = errors.New("invalid currency")
	ErrCurrencyMismatch = errors.New("currency mismatch")
	ErrOverflow         = errors.New("amount overflows int64")
	ErrAllocation       = errors.New("invalid allocation")
	ErrRounding         = errors.New("invalid rounding mode")
)

type Amount struct {
	Minor    int64  `json:"amount" minimum:"-9007199254740991" maximum:"9007199254740991" doc:"Amount in minor units, for example cents"`
	Currency string `json:"currency" minLength:"3" maxLength:"3" pattern:"^[A-Z]{3}$" doc:"ISO 4217 code"`
}

// RoundingMode names how FromDecimal rounds below one minor unit. HalfUp rounds ties away from zero.
type RoundingMode uint8

const (
	HalfEven RoundingMode = iota + 1
	HalfUp
	Down
	Up
)

func New(minor int64, code string) (Amount, error) {
	if _, err := exponent(code); err != nil {
		return Amount{}, err
	}
	return Amount{Minor: minor, Currency: code}, nil
}

func exponent(code string) (int32, error) {
	digits, ok := currency.GetDigits(code)
	if code == "" || !ok {
		return 0, fmt.Errorf("%w: expected a known ISO 4217 code", ErrCurrency)
	}
	return int32(digits), nil
}

func (a Amount) IsZero() bool { return a.Minor == 0 }

func (a Amount) Add(b Amount) (Amount, error) {
	if err := sameCurrency(a, b); err != nil {
		return Amount{}, err
	}
	if (b.Minor > 0 && a.Minor > math.MaxInt64-b.Minor) || (b.Minor < 0 && a.Minor < math.MinInt64-b.Minor) {
		return Amount{}, fmt.Errorf("add %d and %d: %w", a.Minor, b.Minor, ErrOverflow)
	}
	return Amount{Minor: a.Minor + b.Minor, Currency: a.Currency}, nil
}

func (a Amount) Sub(b Amount) (Amount, error) {
	if err := sameCurrency(a, b); err != nil {
		return Amount{}, err
	}
	if (b.Minor > 0 && a.Minor < math.MinInt64+b.Minor) || (b.Minor < 0 && a.Minor > math.MaxInt64+b.Minor) {
		return Amount{}, fmt.Errorf("subtract %d from %d: %w", b.Minor, a.Minor, ErrOverflow)
	}
	return Amount{Minor: a.Minor - b.Minor, Currency: a.Currency}, nil
}

func sameCurrency(a, b Amount) error {
	if a.Currency != b.Currency {
		return fmt.Errorf("%w: %s and %s", ErrCurrencyMismatch, a.Currency, b.Currency)
	}
	_, err := exponent(a.Currency)
	return err
}

func (a Amount) Neg() (Amount, error) {
	if a.Minor == math.MinInt64 {
		return Amount{}, fmt.Errorf("negate %d: %w", a.Minor, ErrOverflow)
	}
	return Amount{Minor: -a.Minor, Currency: a.Currency}, nil
}

// Allocate splits a by weight using largest remainder; ties go to the earlier weight and the parts always sum to a exactly.
func (a Amount) Allocate(weights ...int) ([]Amount, error) {
	if _, err := exponent(a.Currency); err != nil {
		return nil, err
	}
	if len(weights) == 0 {
		return nil, fmt.Errorf("%w: no weights", ErrAllocation)
	}
	total := new(big.Int)
	for _, w := range weights {
		if w < 0 {
			return nil, fmt.Errorf("%w: negative weight %d", ErrAllocation, w)
		}
		total.Add(total, big.NewInt(int64(w)))
	}
	if total.Sign() == 0 {
		return nil, fmt.Errorf("%w: weights sum to zero", ErrAllocation)
	}

	magnitude := new(big.Int).Abs(big.NewInt(a.Minor))
	shares := make([]*big.Int, len(weights))
	remainders := make([]*big.Int, len(weights))
	assigned := new(big.Int)
	for i, w := range weights {
		product := new(big.Int).Mul(magnitude, big.NewInt(int64(w)))
		shares[i], remainders[i] = new(big.Int).QuoRem(product, total, new(big.Int))
		assigned.Add(assigned, shares[i])
	}

	leftover := new(big.Int).Sub(magnitude, assigned).Int64()
	order := make([]int, len(weights))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(x, y int) int { return remainders[y].Cmp(remainders[x]) })
	for _, i := range order[:leftover] {
		shares[i].Add(shares[i], big.NewInt(1))
	}

	parts := make([]Amount, len(weights))
	for i, share := range shares {
		if a.Minor < 0 {
			share.Neg(share)
		}
		parts[i] = Amount{Minor: share.Int64(), Currency: a.Currency}
	}
	return parts, nil
}

// Decimal is the amount in major units.
func (a Amount) Decimal() (decimal.Decimal, error) {
	major, _, err := a.major()
	return major, err
}

func (a Amount) major() (decimal.Decimal, int32, error) {
	exp, err := exponent(a.Currency)
	if err != nil {
		return decimal.Decimal{}, 0, err
	}
	return decimal.New(a.Minor, -exp), exp, nil
}

// FromDecimal converts a decimal in major units, rounding once with mode to the currency's exponent.
func FromDecimal(d decimal.Decimal, code string, mode RoundingMode) (Amount, error) {
	exp, err := exponent(code)
	if err != nil {
		return Amount{}, err
	}
	shifted := d.Shift(exp)

	var rounded decimal.Decimal
	switch mode {
	case HalfEven:
		rounded = shifted.RoundBank(0)
	case HalfUp:
		rounded = shifted.Round(0)
	case Down:
		rounded = shifted.Truncate(0)
	case Up:
		if shifted.IsNegative() {
			rounded = shifted.Floor()
		} else {
			rounded = shifted.Ceil()
		}
	default:
		return Amount{}, fmt.Errorf("%w: %d", ErrRounding, mode)
	}

	minor := rounded.BigInt()
	if !minor.IsInt64() {
		return Amount{}, fmt.Errorf("convert to %s: %w", code, ErrOverflow)
	}
	return Amount{Minor: minor.Int64(), Currency: code}, nil
}

func (a Amount) Format(locale string) string {
	major, exp, err := a.major()
	if err != nil {
		return a.String()
	}
	formatted, err := currency.NewAmount(major.StringFixed(exp), a.Currency)
	if err != nil {
		return a.String()
	}
	return currency.NewFormatter(currency.NewLocale(locale)).Format(formatted)
}

func (a Amount) String() string {
	major, exp, err := a.major()
	if err != nil {
		return fmt.Sprintf("%d %s", a.Minor, a.Currency)
	}
	return major.StringFixed(exp) + " " + a.Currency
}

// MarshalJSON refuses an empty or unknown currency, so the zero Amount can never be written out.
func (a Amount) MarshalJSON() ([]byte, error) {
	if _, err := exponent(a.Currency); err != nil {
		return nil, fmt.Errorf("encode money: %w", err)
	}
	type plain Amount
	return json.Marshal(plain(a))
}

func (a *Amount) UnmarshalJSON(data []byte) error {
	var raw struct {
		Minor    *int64  `json:"amount"`
		Currency *string `json:"currency"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("decode money: %w", err)
	}
	if raw.Minor == nil || raw.Currency == nil {
		return errors.New("decode money: amount and currency are both required")
	}
	parsed, err := New(*raw.Minor, *raw.Currency)
	if err != nil {
		return fmt.Errorf("decode money: %w", err)
	}
	*a = parsed
	return nil
}
