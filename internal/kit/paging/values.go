package paging

import (
	"database/sql/driver"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

// A cursor value carries its type so it binds as the same Go type it was read as.
const (
	typeUUID    = "u"
	typeInt     = "i"
	typeBool    = "b"
	typeString  = "s"
	typeTime    = "t"
	typeDecimal = "d"
)

type value struct {
	T string `json:"t"`
	V string `json:"v"`
}

func encodeValue(v any) (*value, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case uuid.UUID:
		return &value{typeUUID, x.String()}, nil
	case interface{ UUID() uuid.UUID }:
		return &value{typeUUID, x.UUID().String()}, nil
	case time.Time:
		return &value{typeTime, x.UTC().Format(time.RFC3339Nano)}, nil
	case bool:
		return &value{typeBool, strconv.FormatBool(x)}, nil
	case string:
		return &value{typeString, x}, nil
	case int:
		return intValue(int64(x))
	case int8:
		return intValue(int64(x))
	case int16:
		return intValue(int64(x))
	case int32:
		return intValue(int64(x))
	case int64:
		return intValue(x)
	case uint8:
		return intValue(int64(x))
	case uint16:
		return intValue(int64(x))
	case uint32:
		return intValue(int64(x))
	case uint64:
		if x > math.MaxInt64 {
			return nil, fmt.Errorf("paging: %d does not fit a signed 64-bit cursor value", x)
		}
		return intValue(int64(x))
	case decimal.Decimal:
		return &value{typeDecimal, x.String()}, nil
	case driver.Valuer:
		dv, err := x.Value()
		if err != nil {
			return nil, fmt.Errorf("paging: sort value: %w", err)
		}
		if _, again := dv.(driver.Valuer); again {
			return nil, fmt.Errorf("paging: cannot page by a %T", v)
		}
		return encodeValue(dv)
	}
	return nil, fmt.Errorf("paging: cannot page by a %T (convert it in the key's Value; use paging.Opt for pointers)", v)
}

func intValue(n int64) (*value, error) { return &value{typeInt, strconv.FormatInt(n, 10)}, nil }

// decodeValue returns the Go value to bind; MySQL has no boolean type, so booleans bind as 0 or 1 there.
func decodeValue(v value, dialect db.Dialect) (any, error) {
	switch v.T {
	case typeUUID:
		return uuid.Parse(v.V)
	case typeInt:
		return strconv.ParseInt(v.V, 10, 64)
	case typeBool:
		b, err := strconv.ParseBool(v.V)
		if err != nil || dialect != db.MySQL {
			return b, err
		}
		if b {
			return int64(1), nil
		}
		return int64(0), nil
	case typeString:
		return v.V, nil
	case typeTime:
		return time.Parse(time.RFC3339Nano, v.V)
	case typeDecimal:
		return decimal.NewFromString(v.V)
	}
	return nil, ErrCursorInvalid
}
