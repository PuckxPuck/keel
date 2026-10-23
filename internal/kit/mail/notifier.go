package mail

import (
	"context"
	"net/url"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// Links builds the link a token is sent in.
type Links func(purpose tokens.Purpose, token string) string

// DefaultLinks points at <publicURL>/reset-password, /verify-email and /accept-invite with the token in
// the fragment, which browsers never send to a server, so it stays out of access logs and Referer.
func DefaultLinks(publicURL string) Links {
	base := strings.TrimRight(publicURL, "/")
	return func(p tokens.Purpose, token string) string {
		page := map[tokens.Purpose]string{tokens.PasswordReset: "/reset-password", tokens.VerifyEmail: "/verify-email", tokens.Invite: "/accept-invite"}[p]
		return base + page + "#token=" + url.QueryEscape(token)
	}
}

var _ tokens.Notifier = (*Notifier)(nil)

// Notifier sends reset, verification and invite links as mail enqueued in the caller's transaction.
type Notifier struct {
	svc   *Service
	links Links
}

func (s *Service) Notifier(links Links) *Notifier { return &Notifier{svc: s, links: links} }

type linkData struct {
	Name string
	Link string
}

func (n *Notifier) SendReset(ctx context.Context, tx db.Transaction, to users.User, token string) error {
	return n.send(ctx, tx, "reset", tokens.PasswordReset, to, token)
}

func (n *Notifier) SendVerify(ctx context.Context, tx db.Transaction, to users.User, token string) error {
	return n.send(ctx, tx, "verify", tokens.VerifyEmail, to, token)
}

func (n *Notifier) SendInvite(ctx context.Context, tx db.Transaction, to users.User, token string) error {
	return n.send(ctx, tx, "invite", tokens.Invite, to, token)
}

func (n *Notifier) send(ctx context.Context, tx db.Transaction, template string, p tokens.Purpose, to users.User, token string) error {
	name := to.Name
	if name == "" {
		name = "there"
	}
	_, err := n.svc.Enqueue(ctx, tx, Email{
		To: []string{to.Email}, Template: template, Data: linkData{Name: name, Link: n.links(p, token)}, Sensitive: true,
	})
	return err
}
