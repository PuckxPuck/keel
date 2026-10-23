package mail

import (
	"context"

	"github.com/PuckxPuck/keel/internal/kit/jobs"
)

// RunSend runs the mail.send handler for job directly, outside a worker.
func (s *Service) RunSend(ctx context.Context, job jobs.Job) error {
	return jobs.Typed(s.send)(ctx, job)
}
