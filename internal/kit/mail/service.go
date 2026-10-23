package mail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

const (
	KindSend      = "mail.send"
	kindPrune     = "mail.prune"
	maxRecipients = 50
)

type OutboxStatus string

const (
	OutboxQueued    OutboxStatus = "queued"
	OutboxSending   OutboxStatus = "sending"
	OutboxSent      OutboxStatus = "sent"
	OutboxFailed    OutboxStatus = "failed"
	OutboxUncertain OutboxStatus = "uncertain"
)

// Email is what callers enqueue; it is rendered in the caller's transaction.
type Email struct {
	To       []string
	Template string
	Data     any
	// Sensitive clears the stored body as soon as the server accepts it (links that carry a token).
	Sensitive bool
}

type Options struct {
	Queue    *jobs.Queue
	Tx       jobs.TxRunner
	Mailer   Mailer
	Renderer *Renderer
	Config   Config
}

// Service enqueues and sends mail.
type Service struct {
	q        *jobs.Queue
	tx       jobs.TxRunner
	mailer   Mailer
	renderer *Renderer
	from     string
	domain   string
	retain   time.Duration
}

var (
	ErrUncertain   = errors.New("mail: an earlier attempt may have sent this message; not sending again")
	ErrInvalid     = errors.New("mail: invalid email")
	errBodyCleared = errors.New("mail: the message body was cleared; it cannot be sent again")
)

// New registers the send job (bodies cleared after RetainBody) and a daily prune of the outbox.
func New(o Options) (*Service, error) {
	if o.Queue == nil || o.Tx == nil || o.Mailer == nil || o.Renderer == nil {
		return nil, errors.New("mail: queue, transaction runner, mailer and renderer are required")
	}
	from, err := mail.ParseAddress(o.Config.From)
	if err != nil {
		return nil, errors.New("mail: from must be a valid address")
	}
	_, domain, _ := strings.Cut(from.Address, "@")
	s := &Service{q: o.Queue, tx: o.Tx, mailer: o.Mailer, renderer: o.Renderer, from: from.String(), domain: domain, retain: o.Config.RetainLog}
	// Global: a sign-in link may go to a user who has no tenant yet.
	o.Queue.Handle(KindSend, jobs.Typed(s.send), jobs.RetainPayload(o.Config.RetainBody), jobs.Timeout(2*time.Minute), jobs.Global())
	o.Queue.Handle(kindPrune, func(ctx context.Context, _ jobs.Job) error { return s.prune(ctx) }, jobs.Global())
	o.Queue.Schedule(kindPrune, kindPrune, "41 3 * * *", time.UTC)
	return s, nil
}

type payload struct {
	MessageID string   `json:"messageId"`
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Text      string   `json:"text"`
	HTML      string   `json:"html,omitempty"`
	Sensitive bool     `json:"sensitive,omitempty"`
}

// Enqueue renders e and queues it in tx with a Message-ID fixed for every attempt.
func (s *Service) Enqueue(ctx context.Context, tx db.Transaction, e Email) (jobs.ID, error) {
	if len(e.To) == 0 || len(e.To) > maxRecipients {
		return jobs.ID{}, fmt.Errorf("%w: 1 to %d recipients", ErrInvalid, maxRecipients)
	}
	to := make([]string, len(e.To))
	for i, raw := range e.To {
		a, err := mail.ParseAddress(raw)
		if err != nil {
			return jobs.ID{}, fmt.Errorf("%w: recipient %d is not an address", ErrInvalid, i+1)
		}
		to[i] = a.String()
	}
	r, err := s.renderer.Render(e.Template, e.Data)
	if err != nil {
		return jobs.ID{}, err
	}
	p := payload{MessageID: ids.New().String() + "@" + s.domain, To: to, Subject: r.Subject, Text: r.Text, HTML: r.HTML, Sensitive: e.Sensitive}
	id, err := s.q.Enqueue(ctx, tx, KindSend, p)
	if err != nil {
		return jobs.ID{}, err
	}
	return id, record(ctx, tx, p.MessageID, id, 1, OutboxQueued, nil)
}

// send writes "sending" before talking to the server. A run that finds an attempt still "sending" knows
// an earlier one may have handed the message over, marks it uncertain and stops. Each transition takes the
// next seq of the message, so of two runs at once only one moves it; the other stops as uncertain.
func (s *Service) send(ctx context.Context, job jobs.Job, p payload) error {
	if p.MessageID == "" {
		return jobs.Permanent(errBodyCleared)
	}
	var last OutboxStatus
	var seq int
	err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		if last, seq, err = latest(ctx, tx, p.MessageID); err != nil {
			return err
		}
		switch last {
		case OutboxSent, OutboxUncertain:
			return nil
		case OutboxSending:
			return settle(ctx, tx, job.ID, p, seq+1, OutboxUncertain, ErrUncertain)
		case OutboxQueued, OutboxFailed, "":
		}
		return record(ctx, tx, p.MessageID, job.ID, seq+1, OutboxSending, nil)
	})
	switch {
	case db.IsUniqueViolation(err):
		return s.uncertain(ctx, job, p, nil)
	case err != nil:
		return err
	case last == OutboxSent:
		return nil
	case last == OutboxSending || last == OutboxUncertain:
		return s.uncertain(ctx, job, p, nil)
	}
	seq++

	sendErr := s.mailer.Send(ctx, Message{MessageID: p.MessageID, From: s.from, To: p.To, Subject: p.Subject, Text: p.Text, HTML: p.HTML})
	refused, temporary := notSent(sendErr)
	status := OutboxSent
	switch {
	case sendErr == nil:
	case refused:
		status = OutboxFailed
	default:
		status = OutboxUncertain
	}
	recordErr := s.tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
		return settle(ctx, tx, job.ID, p, seq+1, status, sendErr)
	})
	switch {
	case status == OutboxUncertain:
		return s.uncertain(ctx, job, p, errors.Join(sendErr, recordErr))
	case db.IsUniqueViolation(recordErr):
		return s.uncertain(ctx, job, p, sendErr)
	case recordErr != nil:
		// The next run finds "sending" and stops as uncertain rather than send again.
		return fmt.Errorf("mail: record outcome: %w", recordErr)
	case status == OutboxFailed && temporary:
		return sendErr
	case status == OutboxFailed:
		return jobs.Permanent(sendErr)
	}
	return nil
}

func (s *Service) uncertain(ctx context.Context, job jobs.Job, p payload, cause error) error {
	log := logx.From(ctx).With("message_id", p.MessageID, "job_id", job.ID.String())
	if cause != nil {
		log = log.With("error", jobs.Redact(cause.Error()))
	}
	log.Warn("mail: delivery uncertain; not resending")
	return jobs.Permanent(ErrUncertain)
}

// settle records a transition and clears a sensitive body once no run will send it again.
func settle(ctx context.Context, tx db.Transaction, job jobs.ID, p payload, seq int, status OutboxStatus, cause error) error {
	if err := record(ctx, tx, p.MessageID, job, seq, status, cause); err != nil {
		return err
	}
	if p.Sensitive && (status == OutboxSent || status == OutboxUncertain) {
		return jobs.ClearPayload(ctx, tx, job)
	}
	return nil
}

func latest(ctx context.Context, tx db.Transaction, messageID string) (OutboxStatus, int, error) {
	q := db.Rebind(tx.Dialect(), "SELECT status, seq FROM mail_outbox WHERE message_id = ? ORDER BY seq DESC LIMIT 1")
	rows, err := tx.Q().QueryContext(ctx, q, messageID)
	if err != nil {
		return "", 0, fmt.Errorf("mail: outbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return "", 0, rows.Err()
	}
	var status OutboxStatus
	var seq int
	if err := rows.Scan(&status, &seq); err != nil {
		return "", 0, err
	}
	return status, seq, rows.Close()
}

func record(ctx context.Context, tx db.Transaction, messageID string, job jobs.ID, seq int, status OutboxStatus, cause error) error {
	var code, text sql.NullString
	if cause != nil {
		code = sql.NullString{String: string(status), Valid: true}
		text = sql.NullString{String: jobs.Redact(cause.Error()), Valid: true}
	}
	q := db.Rebind(tx.Dialect(), "INSERT INTO mail_outbox (id, message_id, seq, job_id, status, error_code, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	now := clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
	if _, err := tx.Q().ExecContext(ctx, q, ids.New(), messageID, seq, job, string(status), code, text, now); err != nil {
		return fmt.Errorf("mail: outbox: %w", err)
	}
	return nil
}

func (s *Service) prune(ctx context.Context) error {
	before := clock.Wall(ctx).Now().UTC().Add(-s.retain)
	for {
		var n int64
		err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			q := "DELETE FROM mail_outbox WHERE id IN (SELECT id FROM mail_outbox WHERE created_at < ? LIMIT 1000)"
			if tx.Dialect() == db.MySQL {
				q = "DELETE FROM mail_outbox WHERE created_at < ? ORDER BY created_at LIMIT 1000"
			}
			res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), before)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil || n < 1000 {
			return err
		}
	}
}
