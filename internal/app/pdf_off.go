//go:build nopdf

package app

import "context"

type (
	PDFConfig struct{}
	pdfWiring struct{}
)

func (w *wiring) openPDF(Config) error { return nil }

func pdfParts(Config) []string { return nil }

func pdfChecks(context.Context, Config) []Check { return nil }
