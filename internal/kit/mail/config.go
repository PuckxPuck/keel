package mail

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

type Driver string

const (
	DriverSMTP Driver = "smtp"
	DriverLog  Driver = "log"
)

type TLSMode string

const (
	// TLSStartTLS upgrades the connection and refuses a server that does not offer STARTTLS.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit connects with TLS from the start (port 465).
	TLSImplicit TLSMode = "tls"
	// TLSNone sends in clear text; allowed only to a loopback host such as Mailpit.
	TLSNone TLSMode = "none"
)

// Config is APP_MAIL_*.
type Config struct {
	Driver     Driver        `env:"DRIVER" envDefault:"log"`
	From       string        `env:"FROM"`
	SMTP       SMTPConfig    `envPrefix:"SMTP_"`
	RetainBody time.Duration `env:"RETAIN_BODY" envDefault:"72h"`
	RetainLog  time.Duration `env:"RETAIN_LOG" envDefault:"720h"`
}

type SMTPConfig struct {
	Host     string        `env:"HOST"`
	Port     int           `env:"PORT" envDefault:"587"`
	User     string        `env:"USER"`
	Password config.Secret `env:"PASSWORD"`
	TLS      TLSMode       `env:"TLS" envDefault:"starttls"`
	Timeout  time.Duration `env:"TIMEOUT" envDefault:"15s"`
}

func (c Config) Validate(prod bool) error {
	var errs []error
	switch c.Driver {
	case DriverSMTP:
		errs = append(errs, c.SMTP.validate())
	case DriverLog:
		if prod {
			errs = append(errs, errors.New("mail driver log is refused in production; configure smtp"))
		}
	default:
		errs = append(errs, fmt.Errorf("mail driver must be smtp or log, got %q", c.Driver))
	}
	if c.From != "" || c.Driver == DriverSMTP {
		if _, err := mail.ParseAddress(c.From); err != nil {
			errs = append(errs, errors.New("mail from must be an address such as App <no-reply@example.com>"))
		}
	}
	if c.RetainBody < time.Hour || c.RetainLog < c.RetainBody {
		errs = append(errs, errors.New("mail retain body must be at least 1h and retain log at least as long"))
	}
	return errors.Join(errs...)
}

func (s SMTPConfig) validate() error {
	var errs []error
	if s.Host == "" {
		errs = append(errs, errors.New("mail SMTP host is required"))
	}
	if s.Port < 1 || s.Port > 65535 {
		errs = append(errs, errors.New("mail SMTP port must be 1 to 65535"))
	}
	if s.Timeout <= 0 || s.Timeout > 5*time.Minute {
		errs = append(errs, errors.New("mail SMTP timeout must be between 1ns and 5m"))
	}
	switch s.TLS {
	case TLSStartTLS, TLSImplicit:
	case TLSNone:
		if !isLoopback(s.Host) {
			errs = append(errs, errors.New("mail SMTP TLS none is allowed only to a loopback host"))
		}
	default:
		errs = append(errs, fmt.Errorf("mail SMTP TLS must be starttls, tls or none, got %q", s.TLS))
	}
	return errors.Join(errs...)
}

func isLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
