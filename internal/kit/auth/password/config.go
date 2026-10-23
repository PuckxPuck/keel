package password

import (
	"errors"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

// Config is APP_PASSWORD_*.
type Config struct {
	Enabled       bool            `env:"ENABLED" envDefault:"true"`
	MaxConcurrent int             `env:"MAX_CONCURRENT" envDefault:"4"`
	MinLength     int             `env:"MIN_LENGTH"`
	Argon2        Params          `env:"ARGON2" envDefault:"m=19456,t=2,p=1"`
	MemoryBudget  config.ByteSize `env:"MEMORY_BUDGET" envDefault:"256MiB"`
}

// minProductionCost is OWASP's lowest memory-time product for argon2id (m=7168 KiB, t=5).
const minProductionCost = 7168 * 5

func (c Config) Validate(prod bool) error {
	var errs []error
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 256 {
		errs = append(errs, errors.New("max concurrent must be 1 to 256"))
	}
	if c.MinLength != 0 && (c.MinLength < MinWithMFA || c.MinLength > MaxChars) {
		errs = append(errs, fmt.Errorf("min length must be %d to %d, or unset to follow the realm's MFA", MinWithMFA, MaxChars))
	}
	if err := c.Argon2.check(); err != nil {
		errs = append(errs, err)
	} else {
		if prod && uint64(c.Argon2.Memory)*uint64(c.Argon2.Time) < minProductionCost {
			errs = append(errs, errors.New("argon2 parameters are below OWASP's minimum (m*t of at least 7168*5) in production"))
		}
		if need := config.ByteSize(int64(c.Argon2.Memory) << 10 * int64(c.MaxConcurrent)); need > c.MemoryBudget {
			errs = append(errs, fmt.Errorf("argon2 memory times max concurrent (%s) is over the memory budget (%s)", need, c.MemoryBudget))
		}
	}
	return errors.Join(errs...)
}

// Policy is the length rule for a realm: the configured minimum, else 8 when it requires a second
// factor and 15 when it does not.
func (c Config) Policy(mfaRequired bool) Policy {
	switch {
	case c.MinLength != 0:
		return Policy{MinLength: c.MinLength}
	case mfaRequired:
		return Policy{MinLength: MinWithMFA}
	}
	return Policy{MinLength: MinSingleFactor}
}
