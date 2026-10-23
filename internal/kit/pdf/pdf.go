// Package pdf renders HTML to PDF through Gotenberg. Which URLs Chromium may load is Gotenberg's own
// configuration (an allow-list in compose and deploy), so documents only use the assets sent with them.
package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

// Config is the PDF part of an app's configuration; field tags follow kit/config.
type Config struct {
	URL      string          `env:"URL"`
	User     string          `env:"USER"`
	Password config.Secret   `env:"PASSWORD"`
	Timeout  time.Duration   `env:"TIMEOUT" envDefault:"30s"`
	MaxBytes config.ByteSize `env:"MAX_BYTES" envDefault:"32MiB"`
}

func (c Config) Validate(prod bool) error {
	var errs []error
	if c.URL != "" {
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, errors.New("url must be an absolute http(s) URL"))
		}
	}
	if (c.User == "") != (c.Password == "") {
		errs = append(errs, errors.New("user and password are set together"))
	}
	if c.Password != "" {
		if err := config.RequireStrong("password", c.Password, prod); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Timeout <= 0 || c.MaxBytes <= 0 {
		errs = append(errs, errors.New("timeout and max bytes must be positive"))
	}
	return errors.Join(errs...)
}

// ErrUnavailable means Gotenberg could not be reached or failed on its side; the caller may retry later.
var ErrUnavailable = errors.New("pdf: renderer unavailable")

var (
	ErrTooLarge = errors.New("pdf: rendered document is too large")
	ErrNotPDF   = errors.New("pdf: renderer answered with something that is not a PDF")
	ErrRejected = errors.New("pdf: renderer refused the document")
	errAsset    = errors.New("pdf: asset names are plain file names other than index.html")
)

// Asset is a file the HTML refers to by name (an image, a stylesheet, a font).
type Asset struct {
	Name string
	Data []byte
}

type Client struct {
	endpoint string
	user     string
	password config.Secret
	timeout  time.Duration
	maxBytes int64
	http     *http.Client
}

// Gotenberg returns a client for cfg; httpClient may be nil.
func Gotenberg(cfg Config, httpClient *http.Client) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("pdf: url is not set")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{
		endpoint: strings.TrimSuffix(cfg.URL, "/") + "/forms/chromium/convert/html",
		user:     cfg.User, password: cfg.Password, timeout: cfg.Timeout, maxBytes: int64(cfg.MaxBytes), http: httpClient,
	}, nil
}

func (c *Client) HTMLToPDF(ctx context.Context, html []byte, assets ...Asset) ([]byte, error) {
	body, contentType, err := form(html, assets)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if c.user != "" {
		req.SetBasicAuth(c.user, c.password.Reveal())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if int64(len(data)) > c.maxBytes {
		return nil, ErrTooLarge
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, ErrNotPDF
	}
	return data, nil
}

func form(html []byte, assets []Asset) (io.Reader, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	files := append([]Asset{{Name: "index.html", Data: html}}, assets...)
	for i, a := range files {
		if i > 0 && !plainName(a.Name) {
			return nil, "", errAsset
		}
		w, err := mw.CreateFormFile("files", a.Name)
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write(a.Data); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return &buf, mw.FormDataContentType(), nil
}

func plainName(name string) bool {
	return name != "" && name != "index.html" && name != "." && name != ".." && len(name) <= 255 &&
		!strings.ContainsAny(name, "/\\\x00\"\r\n")
}
