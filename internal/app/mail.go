//go:build !nomail

package app

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"io/fs"
	"maps"
	"net"
	"strconv"

	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/mail"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

//go:embed mail/*.txt
var mailTemplates embed.FS

// MailConfig is APP_MAIL_*.
type MailConfig = mail.Config

// Mailer is what Deps.Mailer replaces the configured driver with (tests).
type Mailer = mail.Mailer

// mailWiring is the mail service, set with a database.
type mailWiring struct {
	mail *mail.Service
}

// localSender is the From of mail the log driver records when APP_MAIL_FROM is not set.
const localSender = "no-reply@localhost"

// openMail opens the mail service and, unless the app passed one, makes the notifier from it.
func (w *wiring) openMail(cfg Config, deps Deps) error {
	sub, err := fs.Sub(mailTemplates, "mail")
	if err != nil {
		return err
	}
	renderer, err := mail.NewRenderer(sub)
	if err != nil {
		return err
	}
	mailer := deps.Mailer
	if mailer == nil {
		if mailer, err = newMailer(cfg.Mail); err != nil {
			return err
		}
	}
	mc := cfg.Mail
	if mc.From == "" {
		mc.From = localSender
	}
	if w.mail, err = mail.New(mail.Options{Queue: w.queue, Tx: jobTx(deps), Mailer: mailer, Renderer: renderer, Config: mc}); err != nil {
		return err
	}
	if w.admins == nil {
		w.admins = mailAdmins{mail: w.mail}
	}
	if w.notifier != nil {
		return nil
	}
	// Locally the log driver records no links, so the log notifier prints them instead.
	if cfg.Env == config.EnvLocal && cfg.Mail.Driver == mail.DriverLog {
		w.notifier = tokens.LogNotifier{}
		return nil
	}
	w.notifier = w.mail.Notifier(mail.DefaultLinks(cfg.App.PublicURL))
	return nil
}

func newMailer(cfg mail.Config) (mail.Mailer, error) {
	if cfg.Driver == mail.DriverSMTP {
		return mail.NewSMTP(cfg.SMTP)
	}
	return mail.Log{}, nil
}

// mailAdmins mails an AdminNotice to every active user holding its permission on the tenant realm (the
// context's tenant's under tenancy), one message each so no recipient sees the others; Kind names the
// template, which reads Name and the notice's fields.
type mailAdmins struct{ mail *mail.Service }

func (m mailAdmins) NotifyAdmins(ctx context.Context, tx db.Transaction, n AdminNotice) (int, error) {
	holders, err := rbac.Holders(ctx, tx, RealmTenant, n.Perm)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, id := range holders {
		u, err := users.Get(ctx, tx, id)
		if errors.Is(err, users.ErrNotFound) {
			continue
		}
		if err != nil {
			return queued, err
		}
		data := maps.Clone(n.Fields)
		if data == nil {
			data = map[string]string{}
		}
		data["Name"] = cmp.Or(u.Name, "there")
		if _, err := m.mail.Enqueue(ctx, tx, mail.Email{To: []string{u.Email}, Template: n.Kind, Data: data}); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func mailParts(cfg Config) []string { return []string{"mail:" + string(cfg.Mail.Driver)} }

func mailChecks(ctx context.Context, cfg Config) []Check { return []Check{checkMail(ctx, cfg.Mail)} }

// checkMail connects, upgrades to TLS as configured (verifying the certificate) and signs in when a user
// is set, then quits before MAIL FROM: nothing is sent.
func checkMail(ctx context.Context, cfg mail.Config) Check {
	if cfg.Driver != mail.DriverSMTP {
		return warn("mail", "the log driver records mail and sends none")
	}
	smtpCfg := cfg.SMTP
	smtpCfg.Timeout = min(smtpCfg.Timeout, probeTimeout)
	addr := net.JoinHostPort(smtpCfg.Host, strconv.Itoa(smtpCfg.Port))
	client, err := mail.NewSMTP(smtpCfg)
	if err != nil {
		return fail("mail", err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		return fail("mail", addr+": "+err.Error())
	}
	detail := addr + " reachable"
	switch smtpCfg.TLS {
	case mail.TLSStartTLS:
		detail += ", STARTTLS with a verified certificate"
	case mail.TLSImplicit:
		detail += ", TLS with a verified certificate"
	case mail.TLSNone:
		detail += ", no TLS (loopback)"
	}
	if smtpCfg.User != "" {
		detail += ", signed in"
	}
	return pass("mail", detail)
}
