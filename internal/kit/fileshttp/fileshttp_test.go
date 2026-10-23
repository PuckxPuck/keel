package fileshttp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/kit/fileshttp"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

type fixture struct {
	svc     *files.Service
	signer  *files.URLSigner
	private files.File
	public  files.File
	refused files.File // of refusedTenant
	mux     *http.ServeMux
}

func newService(t *testing.T, local files.Storage, signer *files.URLSigner, run files.TxRunner) *files.Service {
	t.Helper()
	svc, err := files.NewService(files.Options{
		Storage: local, Inspector: inspect.New(inspect.Limits{}, 1), TempDir: t.TempDir(), Signer: signer, Tx: run,
		Policies: map[string]files.Policy{
			"doc":  {MaxBytes: 1 << 10, Types: []string{inspect.TypeText}, Visibility: files.Private},
			"open": {MaxBytes: 1 << 10, Types: []string{inspect.TypeText}, Visibility: files.Public},
		},
	})
	require.NoError(t, err)
	return svc
}

func newLocal(t *testing.T) *files.Local {
	t.Helper()
	local, err := files.NewLocal(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = local.Close() })
	return local
}

var errNoDatabase = errors.New("downloads need no database")

// refusedTenant is a tenant whose links the fixture's Admit refuses, as an app does on another tenant's
// host or for a suspended tenant.
var refusedTenant = uuid.New()

// setup serves objects written straight to storage, with rows held in memory.
func setup(t *testing.T) fixture {
	t.Helper()
	local := newLocal(t)
	signer, err := files.NewURLSigner("https://app.example.com/files/public", bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)
	svc := newService(t, local, signer, func(context.Context, func(context.Context, db.Transaction) error) error { return errNoDatabase })
	fileOf := func(kind, name, body string, visibility files.Visibility) files.File {
		r := strings.ReplaceAll(uuid.NewString(), "-", "")
		key := "f/" + r[:2] + "/" + r[2:4] + "/" + r
		if name == "elsewhere.txt" {
			key = "f/" + refusedTenant.String() + "/" + r[:2] + "/" + r[2:4] + "/" + r
		}
		require.NoError(t, local.Put(t.Context(), key, files.PutInput{Body: strings.NewReader(body), Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}))
		id, err := files.ParseID(ids.New().String())
		require.NoError(t, err)
		return files.File{ID: id, Kind: kind, Name: name, Mime: inspect.TypeText, Size: int64(len(body)), Key: key, Visibility: visibility}
	}
	fx := fixture{
		svc: svc, signer: signer,
		private: fileOf("doc", `résumé "final"%.txt`, "private body", files.Private),
		public:  fileOf("open", "logo.txt", "public body", files.Public),
		refused: fileOf("open", "elsewhere.txt", "another tenant's body", files.Public),
	}
	byID := map[files.ID]files.File{fx.private.ID: fx.private, fx.public.ID: fx.public, fx.refused.ID: fx.refused}
	load := func(_ context.Context, id files.ID) (files.File, error) {
		f, ok := byID[id]
		if !ok {
			return files.File{}, files.ErrNotFound
		}
		return f, nil
	}
	allowed := fx.private.ID
	authorize := func(ctx context.Context, id files.ID) (files.File, error) {
		if id != allowed {
			return files.File{}, files.ErrNotFound
		}
		return load(ctx, id)
	}
	admit := func(_ context.Context, tenant uuid.UUID) error {
		if tenant == refusedTenant {
			return files.ErrNotFound
		}
		return nil
	}
	opts := fileshttp.Options{Files: svc, Authorize: authorize, Load: load, Signer: signer, Admit: admit}
	fx.mux = http.NewServeMux()
	fx.mux.Handle("GET /files/{"+fileshttp.IDParam+"}", fileshttp.Private(opts))
	fx.mux.Handle("GET /files/public/{"+fileshttp.IDParam+"}", fileshttp.Public(opts))
	return fx
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	return rec
}

func TestPrivate_ServesAnAttachmentThatCannotRun(t *testing.T) {
	fx := setup(t)
	rec := get(t, fx.mux, "/files/"+fx.private.ID.String())
	require.Equal(t, http.StatusOK, rec.Code)
	h := rec.Result().Header
	assert.Equal(t, `attachment; filename="r_sum_ _final__.txt"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%22final%22%25.txt`, h.Get("Content-Disposition"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "sandbox; default-src 'none'", h.Get("Content-Security-Policy"))
	assert.Equal(t, inspect.TypeText, h.Get("Content-Type"))
	assert.Equal(t, "12", h.Get("Content-Length"))
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	assert.Equal(t, "private body", string(body))
}

func TestPrivate_RefusedFileDoesNotExist(t *testing.T) {
	fx := setup(t)
	for _, target := range []string{"/files/" + fx.public.ID.String(), "/files/not-an-id"} {
		rec := get(t, fx.mux, target)
		assert.Equal(t, http.StatusNotFound, rec.Code, target)
		assert.Equal(t, "application/problem+json", rec.Result().Header.Get("Content-Type"))
	}
}

func TestPublic_SignedLinks(t *testing.T) {
	fx := setup(t)
	now := clock.Wall(t.Context()).Now()
	linkIn := func(f files.File, tenant uuid.UUID, at time.Time, ttl time.Duration) string {
		raw, err := fx.signer.URL(f.ID, tenant, at, ttl)
		require.NoError(t, err)
		u, err := url.Parse(raw)
		require.NoError(t, err)
		return u.RequestURI()
	}
	link := func(f files.File, at time.Time, ttl time.Duration) string { return linkIn(f, uuid.Nil, at, ttl) }
	tampered := func(key, value string) string {
		u, err := url.Parse(link(fx.public, now, time.Minute))
		require.NoError(t, err)
		q := u.Query()
		q.Set(key, value)
		u.RawQuery = q.Encode()
		return u.RequestURI()
	}
	rotated, err := files.NewURLSigner("https://app.example.com/files/public", bytes.Repeat([]byte("n"), 32), bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)
	_, err = fx.signer.URL(fx.public.ID, uuid.Nil, now, files.MaxLinkTTL+time.Second)
	require.Error(t, err, "a link outliving the cap must not be made")

	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"valid", link(fx.public, now, time.Minute), http.StatusOK},
		{"expired", link(fx.public, now.Add(-time.Hour), time.Minute), http.StatusNotFound},
		{"expiry changed", tampered("expires", "9999999999"), http.StatusNotFound},
		{"oversized signature", tampered("sig", strings.Repeat("A", 4096)), http.StatusNotFound},
		{"private file", link(fx.private, now, time.Minute), http.StatusNotFound},
		{"unsigned", "/files/public/" + fx.public.ID.String(), http.StatusNotFound},
		{"a tenant Admit refuses here", linkIn(fx.refused, refusedTenant, now, time.Minute), http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, get(t, fx.mux, c.target).Code)
		})
	}
	u, err := url.Parse(link(fx.public, now, time.Minute))
	require.NoError(t, err)
	require.NoError(t, verifyLink(rotated, fx.public.ID, u, now), "an older key still verifies")
	assert.Panics(t, func() {
		fileshttp.Public(fileshttp.Options{Files: fx.svc, Load: func(context.Context, files.ID) (files.File, error) { return fx.public, nil }, Signer: fx.signer})
	}, "a public route without Admit is a wiring error")
}

type uploadCase struct {
	name   string
	body   io.Reader
	header map[string]string
	who    error
	want   int
	saved  string
}

func multipartBody(t *testing.T, parts ...[2]string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		var w io.Writer
		var err error
		if p[0] == "" {
			w, err = mw.CreateFormField("note")
		} else {
			w, err = mw.CreateFormFile("file", p[0])
		}
		require.NoError(t, err)
		_, err = io.WriteString(w, p[1])
		require.NoError(t, err)
	}
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

// chunked hides the body's length, so only the read itself can enforce the cap.
type chunked struct{ io.Reader }

func TestUpload_StreamsOneFileUnderTheCap(t *testing.T) {
	d := testdb.Get(t)
	svc := newService(t, newLocal(t), nil, files.PlainTx(d))
	alice := files.Uploader{Kind: "user", ID: uuid.New()}
	refuse := problem.New(http.StatusUnauthorized, "unauthorized", "sign in")

	one, oneType := multipartBody(t, [2]string{"a.txt", "from a form"})
	two, twoType := multipartBody(t, [2]string{"a.txt", "first"}, [2]string{"b.txt", "second"})
	field, fieldType := multipartBody(t, [2]string{"", "not a file"}, [2]string{"a.txt", "late"})
	big := strings.Repeat("x", 2<<10)
	cases := []uploadCase{
		{"raw body", strings.NewReader("raw text"), map[string]string{"Content-Disposition": `attachment; filename="raw.txt"`}, nil, http.StatusCreated, "raw.txt"},
		{"one file part", one, map[string]string{"Content-Type": oneType}, nil, http.StatusCreated, "a.txt"},
		{"two file parts", two, map[string]string{"Content-Type": twoType}, nil, http.StatusBadRequest, ""},
		{"field before the file", field, map[string]string{"Content-Type": fieldType}, nil, http.StatusBadRequest, ""},
		{"declared length over the cap", strings.NewReader(big + strings.Repeat("x", 16<<10)), nil, nil, http.StatusRequestEntityTooLarge, ""},
		{"streamed body over the cap", chunked{strings.NewReader(big)}, nil, nil, http.StatusRequestEntityTooLarge, ""},
		{"refused uploader", strings.NewReader("x"), nil, refuse, http.StatusUnauthorized, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := fileshttp.Upload(fileshttp.Options{Files: svc, Uploader: func(context.Context) (files.Uploader, error) { return alice, c.who }}, "doc")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/uploads/doc", c.body)
			for k, v := range c.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, c.want, rec.Code, rec.Body.String())
			if c.saved == "" {
				return
			}
			var out struct{ Data files.Receipt }
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			assert.Equal(t, c.saved, out.Data.Name)
			require.NoError(t, db.InTx(t.Context(), d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				_, err := svc.Stage(ctx, tx, out.Data.ID, alice)
				return err
			}), "the uploader stages the receipt")
		})
	}
}

func verifyLink(s *files.URLSigner, id files.ID, u *url.URL, now time.Time) error {
	_, err := s.Verify(id, u.Query().Get("tenant"), u.Query().Get("expires"), u.Query().Get("sig"), now)
	return err
}
