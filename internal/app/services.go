package app

import (
	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
)

// openServices builds the job queue and the parts that run on it: mail (and the notifier made from it),
// outbound webhooks and connections when their keys are set, and the PDF client when its URL is.
func (w *wiring) openServices(cfg Config, deps Deps) error {
	opts := jobs.Options{Config: cfg.Jobs, Tx: queueTx(deps), Build: buildinfo.Get().BuildTime}
	otelJobs(cfg, &opts)
	q, err := jobs.New(opts)
	if err != nil {
		return err
	}
	w.queue = q
	if err := w.openMail(cfg, deps); err != nil {
		return err
	}
	if err := w.openWebhooks(cfg, deps); err != nil {
		return err
	}
	if err := w.openConnections(cfg, deps); err != nil {
		return err
	}
	if err := w.openPDF(cfg); err != nil {
		return err
	}
	w.apiKeyNotices()
	return nil
}
