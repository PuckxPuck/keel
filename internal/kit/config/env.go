package config

import "fmt"

type Env string

const (
	EnvLocal      Env = "local"
	EnvTest       Env = "test"
	EnvStaging    Env = "staging"
	EnvProduction Env = "production"
)

// IsProd is true for staging and production: both get the production profile.
func (e Env) IsProd() bool { return e == EnvStaging || e == EnvProduction }

func (e Env) Validate(bool) error {
	switch e {
	case EnvLocal, EnvTest, EnvStaging, EnvProduction:
		return nil
	}
	return fmt.Errorf("must be local, test, staging or production, got %q", string(e))
}
