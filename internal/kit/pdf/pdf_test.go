package pdf_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/pdf"
)

// fakeGotenberg checks basic auth and the form, then answers with body and status.
func fakeGotenberg(t *testing.T, status int, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "render" || pass != "render-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		//nolint:gosec // the body is capped by MaxBytesReader above
		if r.URL.Path != "/forms/chromium/convert/html" || r.ParseMultipartForm(1<<20) != nil || len(r.MultipartForm.File["files"]) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestHTMLToPDF(t *testing.T) {
	doc := append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("x"), 100)...)
	cases := []struct {
		name     string
		status   int
		body     []byte
		maxBytes config.ByteSize
		password string
		want     error
	}{
		{"renders", http.StatusOK, doc, 1024, "render-password", nil},
		{"over the size cap", http.StatusOK, doc, 64, "render-password", pdf.ErrTooLarge},
		{"exactly the size cap", http.StatusOK, doc, config.ByteSize(len(doc)), "render-password", nil},
		{"not a pdf", http.StatusOK, []byte("<html>error</html>"), 1024, "render-password", pdf.ErrNotPDF},
		{"renderer down", http.StatusServiceUnavailable, nil, 1024, "render-password", pdf.ErrUnavailable},
		{"wrong credentials", http.StatusOK, doc, 1024, "other-password", pdf.ErrRejected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, err := pdf.Gotenberg(pdf.Config{
				URL: fakeGotenberg(t, c.status, c.body), User: "render", Password: config.Secret(c.password),
				Timeout: 5 * time.Second, MaxBytes: c.maxBytes,
			}, nil)
			require.NoError(t, err)
			got, err := client.HTMLToPDF(t.Context(), []byte("<h1>Invoice</h1><img src=\"logo.png\">"), pdf.Asset{Name: "logo.png", Data: []byte("png")})
			if c.want != nil {
				assert.ErrorIs(t, err, c.want)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, doc, got)
		})
	}
}

func TestHTMLToPDF_UnreachableAndBadAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	client, err := pdf.Gotenberg(pdf.Config{URL: url, Timeout: time.Second, MaxBytes: 1024}, nil)
	require.NoError(t, err)
	_, err = client.HTMLToPDF(t.Context(), []byte("<p>x</p>"))
	require.ErrorIs(t, err, pdf.ErrUnavailable)

	_, err = client.HTMLToPDF(t.Context(), []byte("<p>x</p>"), pdf.Asset{Name: "../etc/passwd", Data: nil})
	require.Error(t, err)
	assert.NotErrorIs(t, err, pdf.ErrUnavailable)
}
