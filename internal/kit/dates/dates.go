package dates

import (
	"cmp"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

var ErrInvalid = errors.New("invalid date")

type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// errFormat never carries the input: Huma copies parser errors into responses.
var errFormat = fmt.Errorf("%w: expected a real calendar date as YYYY-MM-DD, years 0001 to 9999", ErrInvalid)

func New(year int, month time.Month, day int) (Date, error) {
	d := Date{Year: year, Month: month, Day: day}
	if !d.valid() {
		return Date{}, errFormat
	}
	return d, nil
}

func (d Date) valid() bool {
	if d.Year < 1 || d.Year > 9999 {
		return false
	}
	t := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
	return t.Year() == d.Year && t.Month() == d.Month && t.Day() == d.Day
}

// Parse accepts only YYYY-MM-DD.
func Parse(s string) (Date, error) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return Date{}, errFormat
	}
	year, ok1 := digits(s[0:4])
	month, ok2 := digits(s[5:7])
	day, ok3 := digits(s[8:10])
	if !ok1 || !ok2 || !ok3 {
		return Date{}, errFormat
	}
	return New(year, time.Month(month), day)
}

func MustParse(s string) Date {
	d, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

func digits(s string) (int, bool) {
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// FromTime takes the calendar date of t in its own location.
func FromTime(t time.Time) Date {
	y, m, d := t.Date()
	return Date{Year: y, Month: m, Day: d}
}

func (d Date) IsZero() bool { return d == Date{} }

func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day)
}

// In returns midnight at the start of the date in loc.
func (d Date) In(loc *time.Location) time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, loc)
}

func (d Date) AddDays(n int) Date {
	return FromTime(time.Date(d.Year, d.Month, d.Day+n, 0, 0, 0, 0, time.UTC))
}

func (d Date) Weekday() time.Weekday {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC).Weekday()
}

func (d Date) Compare(o Date) int {
	switch {
	case d.Year != o.Year:
		return cmp.Compare(d.Year, o.Year)
	case d.Month != o.Month:
		return cmp.Compare(int(d.Month), int(o.Month))
	default:
		return cmp.Compare(d.Day, o.Day)
	}
}

func (d Date) Before(o Date) bool { return d.Compare(o) < 0 }
func (d Date) After(o Date) bool  { return d.Compare(o) > 0 }
func (d Date) Equal(o Date) bool  { return d == o }

// MarshalText refuses the zero Date and any other invalid one; optional dates are *Date.
func (d Date) MarshalText() ([]byte, error) {
	if !d.valid() {
		return nil, fmt.Errorf("%w: not a real calendar date", ErrInvalid)
	}
	return []byte(d.String()), nil
}

func (d *Date) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func (d *Date) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		date := FromTime(v)
		if !date.valid() {
			return errFormat
		}
		*d = date
		return nil
	case string:
		return d.UnmarshalText([]byte(v))
	case []byte:
		return d.UnmarshalText(v)
	default:
		return fmt.Errorf("%w: cannot scan %T", ErrInvalid, src)
	}
}

func (d Date) Value() (driver.Value, error) {
	if !d.valid() {
		return nil, fmt.Errorf("%w: not a real calendar date", ErrInvalid)
	}
	return d.String(), nil
}

func (Date) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Format: "date"}
}
