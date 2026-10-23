// Package mail sends email from jobs through an append-only outbox, so a message is never sent twice
// without someone being told.
package mail

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/PuckxPuck/keel/internal/kit/logx"
)

// Message is a rendered email. MessageID has no angle brackets.
type Message struct {
	MessageID string
	From      string
	To        []string
	Subject   string
	Text      string
	HTML      string
}

// Mailer hands a message to a server. An error wrapped with NotSent means the server certainly did not
// accept it; any other error leaves the outcome unknown and the message is not retried.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

type notSentError struct {
	err       error
	temporary bool
}

func (e *notSentError) Error() string { return e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

// NotSent marks err as a refusal before the message was handed over; temporary ones are retried.
func NotSent(err error, temporary bool) error {
	return &notSentError{err: err, temporary: temporary}
}

func notSent(err error) (sent, temporary bool) {
	var ns *notSentError
	if errors.As(err, &ns) {
		return true, ns.temporary
	}
	return false, false
}

// Log logs that a message was sent, with its id and recipient count but no addresses or content.
type Log struct{}

func (Log) Send(ctx context.Context, m Message) error {
	logx.From(ctx).Info("mail: sent to log", "message_id", m.MessageID, "recipients", len(m.To))
	return nil
}

// Recorder keeps sent messages in memory for tests. Fail, when set, decides each send's error.
type Recorder struct {
	mu   sync.Mutex
	sent []Message
	Fail func(m Message) error
}

func (r *Recorder) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Fail != nil {
		if err := r.Fail(m); err != nil {
			return err
		}
	}
	m.To = slices.Clone(m.To)
	r.sent = append(r.sent, m)
	return nil
}

func (r *Recorder) Messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent)
}
