//go:build !nopdf

package app

import (
	"context"
	"net/http"
	"strings"

	"github.com/PuckxPuck/keel/internal/kit/pdf"
)

// PDFConfig is APP_PDF_*.
type PDFConfig = pdf.Config

// pdfWiring is the renderer client, set with a database when APP_PDF_URL is.
type pdfWiring struct {
	pdf *pdf.Client
}

func (w *wiring) openPDF(cfg Config) error {
	if cfg.PDF.URL == "" {
		return nil
	}
	var err error
	w.pdf, err = pdf.Gotenberg(cfg.PDF, nil)
	return err
}

func pdfParts(cfg Config) []string {
	if cfg.PDF.URL != "" {
		return []string{"pdf"}
	}
	return nil
}

func pdfChecks(ctx context.Context, cfg Config) []Check { return []Check{checkPDF(ctx, cfg)} }

func checkPDF(ctx context.Context, cfg Config) Check {
	if cfg.PDF.URL == "" {
		return pass("pdf", "off (APP_PDF_URL is empty)")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(cfg.PDF.URL, "/")+"/health", nil)
	if err != nil {
		return fail("pdf", err.Error())
	}
	if cfg.PDF.User != "" {
		req.SetBasicAuth(cfg.PDF.User, cfg.PDF.Password.Reveal())
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fail("pdf", "renderer unreachable: "+err.Error())
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("pdf", "renderer answered "+resp.Status)
	}
	return pass("pdf", "renderer reachable")
}
