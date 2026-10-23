package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	gomail "github.com/wneessen/go-mail"

	"github.com/PuckxPuck/keel/internal/kit/clock"
)

// SMTP sends through one server with the configured TLS policy; a server that does not offer STARTTLS
// is refused unless TLS is none, which config validation allows only to loopback.
type SMTP struct {
	cfg SMTPConfig
}

func NewSMTP(cfg SMTPConfig) (*SMTP, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &SMTP{cfg: cfg}, nil
}

func (s *SMTP) client() (*gomail.Client, error) {
	opts := []gomail.Option{
		gomail.WithPort(s.cfg.Port),
		gomail.WithTimeout(s.cfg.Timeout),
		gomail.WithTLSConfig(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}),
	}
	switch s.cfg.TLS {
	case TLSStartTLS:
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	case TLSImplicit:
		opts = append(opts, gomail.WithSSL())
	case TLSNone:
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	}
	if s.cfg.User != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(s.cfg.User), gomail.WithPassword(s.cfg.Password.Reveal()))
	}
	return gomail.NewClient(s.cfg.Host, opts...)
}

// Probe connects the way Send does (TLS as configured, the certificate verified, AUTH when a user is
// set) and quits before MAIL FROM, so nothing is sent.
func (s *SMTP) Probe(ctx context.Context) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := c.DialWithContext(ctx); err != nil {
		return err
	}
	return c.Close()
}

func (s *SMTP) Send(ctx context.Context, m Message) error {
	msg := gomail.NewMsg()
	if err := msg.From(m.From); err != nil {
		return NotSent(fmt.Errorf("mail: from address: %w", err), false)
	}
	if err := msg.To(m.To...); err != nil {
		return NotSent(errors.New("mail: a recipient address is invalid"), false)
	}
	msg.Subject(m.Subject)
	msg.SetMessageIDWithValue(m.MessageID)
	msg.SetDateWithValue(clock.Wall(ctx).Now())
	msg.SetBodyString(gomail.TypeTextPlain, m.Text)
	if m.HTML != "" {
		msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)
	}
	c, err := s.client()
	if err != nil {
		return NotSent(fmt.Errorf("mail: smtp client: %w", err), false)
	}
	if err := c.DialWithContext(ctx); err != nil {
		return NotSent(fmt.Errorf("mail: connect: %w", err), true)
	}
	defer func() { _ = c.Close() }() // the message's fate is already decided
	if err := c.Send(msg); err != nil {
		return classify(err)
	}
	return nil
}

// classify separates refusals before the message body was accepted from failures while or after it
// was written, where the server may already hold the message.
func classify(err error) error {
	var se *gomail.SendError
	if !errors.As(err, &se) {
		return fmt.Errorf("mail: send: %w", err)
	}
	switch se.Reason {
	case gomail.ErrGetSender, gomail.ErrGetRcpts, gomail.ErrSMTPMailFrom, gomail.ErrSMTPRcptTo, gomail.ErrSMTPData,
		gomail.ErrConnCheck, gomail.ErrNoUnencoded:
		return NotSent(fmt.Errorf("mail: send: %w", err), se.IsTemp())
	case gomail.ErrSMTPDataClose:
		if se.ErrorCode() >= 400 {
			return NotSent(fmt.Errorf("mail: refused: %w", err), se.IsTemp())
		}
	case gomail.ErrSMTPReset, gomail.ErrWriteContent, gomail.ErrAmbiguous:
	}
	return fmt.Errorf("mail: send: %w", err)
}
