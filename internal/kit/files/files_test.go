package files_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"image"
	"image/jpeg"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const (
	kindNote   = "note"
	kindAvatar = "avatar"
	kindPhoto  = "photo"
)

var (
	alice = files.Uploader{Kind: "user", ID: uuid.New()}
	bob   = files.Uploader{Kind: "user", ID: uuid.New()}
)

func newService(t *testing.T, d *db.DB, storage files.Storage, extra map[string]files.Policy) *files.Service {
	t.Helper()
	policies := map[string]files.Policy{
		kindNote:   {MaxBytes: 64 << 20, Types: []string{inspect.TypeText}, Inspect: true, Visibility: files.Private},
		kindAvatar: {MaxBytes: 1 << 20, Types: []string{inspect.TypePNG}, Inspect: true, Visibility: files.Public},
	}
	maps.Copy(policies, extra)
	svc, err := files.NewService(files.Options{
		Storage: storage, Inspector: inspect.New(inspect.Limits{}, 2), TempDir: t.TempDir(), Tx: files.PlainTx(d), Policies: policies,
	})
	require.NoError(t, err)
	return svc
}

func newLocal(t *testing.T) (*files.Local, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := files.NewLocal(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, dir
}

// lines produces size bytes of text without holding them.
type lines struct{ left int64 }

func (l *lines) Read(p []byte) (int, error) {
	if l.left == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), l.left))
	for i := range n {
		p[i] = "abcdefghijklmno\n"[i%16]
	}
	l.left -= int64(n)
	return n, nil
}

func listKeys(t *testing.T, s files.Storage, prefix string) []string {
	t.Helper()
	var keys []string
	require.NoError(t, s.List(t.Context(), prefix, func(o files.ObjectInfo) error {
		keys = append(keys, o.Key)
		return nil
	}))
	return keys
}

func TestPut_StreamsUnderTheCapWithoutBuffering(t *testing.T) {
	local, _ := newLocal(t)
	svc := newService(t, testdb.Get(t), local, nil)
	const size = 48 << 20

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r, err := svc.Put(t.Context(), files.Upload{Kind: kindNote, Name: "big.txt", Body: &lines{left: size}, By: alice})
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	assert.Equal(t, int64(size), r.Size)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20), "the upload was buffered in memory")

	_, err = svc.Put(t.Context(), files.Upload{Kind: kindNote, Name: "huge.txt", Body: &lines{left: 64<<20 + 1}, By: alice})
	require.ErrorIs(t, err, files.ErrTooLarge)
	assert.Len(t, listKeys(t, local, ""), 1, "a refused upload left an object behind")
}

// lowQualityJPEG compresses noise hard, so re-encoding it at the inspector's quality makes it larger.
func lowQualityJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 64, 64))
	for i := range img.Pix {
		img.Pix[i] = byte(i * 7919 % 251)
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: 5}))
	return buf.Bytes()
}

func TestPut_RefusesByContentNotName(t *testing.T) {
	local, _ := newLocal(t)
	photo := lowQualityJPEG(t)
	svc := newService(t, testdb.Get(t), local, map[string]files.Policy{
		kindPhoto: {MaxBytes: int64(len(photo)) + 64, Types: []string{inspect.TypeJPEG}, Inspect: true, Visibility: files.Private},
	})
	cases := []struct {
		name string
		kind string
		body []byte
		by   files.Uploader
		want error
	}{
		{"text named as a png", kindAvatar, []byte("hello"), alice, files.ErrTypeNotAllowed},
		{"binary named as text", kindNote, []byte{0x00, 0x01}, alice, files.ErrTypeNotAllowed},
		{"text with NUL", kindNote, append(bytes.Repeat([]byte("a"), 600), 0), alice, files.ErrRefused},
		{"empty", kindNote, nil, alice, files.ErrEmpty},
		{"unknown kind", "other", []byte("x"), alice, files.ErrUnknownKind},
		{"image that grows past the cap when re-encoded", kindPhoto, photo, alice, files.ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.Put(t.Context(), files.Upload{Kind: c.kind, Name: "x.png", Body: bytes.NewReader(c.body), By: c.by})
			assert.ErrorIs(t, err, c.want)
		})
	}
	_, err := svc.Put(t.Context(), files.Upload{Kind: kindNote, Name: "x.txt", Body: bytes.NewReader([]byte("x"))})
	require.Error(t, err, "an upload needs an uploader")
	assert.Empty(t, listKeys(t, local, ""))
}

func TestLocal_SymlinksCannotEscapeTheRoot(t *testing.T) {
	local, dir := newLocal(t)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "f")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "leak")))

	_, _, err := local.Get(t.Context(), "f/secret")
	require.Error(t, err)
	_, _, err = local.Get(t.Context(), "leak")
	require.Error(t, err)

	body := []byte("planted")
	err = local.Put(t.Context(), "f/planted", files.PutInput{Body: bytes.NewReader(body), Size: int64(len(body)), SHA256: sha256.Sum256(body)})
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(outside, "planted"))
	require.ErrorIs(t, statErr, os.ErrNotExist)

	_, _, err = local.Get(t.Context(), "../secret")
	assert.Error(t, err)
}

func TestStorage_Contract(t *testing.T) {
	local, _ := newLocal(t)
	stores := map[string]files.Storage{"local": local}
	s3store, s3client := s3Store(t)
	if s3store != nil {
		stores["s3"] = s3store
	}
	for name, s := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			prefix := "contract/" + uuid.NewString() + "/"
			body := []byte("contract body")
			in := func(b []byte) files.PutInput {
				return files.PutInput{Body: bytes.NewReader(b), Size: int64(len(b)), SHA256: sha256.Sum256(b), ContentType: "text/plain"}
			}
			require.NoError(t, s.Put(ctx, prefix+"a", in(body)))
			require.NoError(t, s.Put(ctx, prefix+"sub/b", in([]byte("b"))))

			info, err := s.Stat(ctx, prefix+"a")
			require.NoError(t, err)
			assert.Equal(t, int64(len(body)), info.Size)

			rc, info, err := s.Get(ctx, prefix+"a")
			require.NoError(t, err)
			got, err := io.ReadAll(rc)
			require.NoError(t, rc.Close())
			require.NoError(t, err)
			assert.Equal(t, body, got)
			assert.Equal(t, int64(len(body)), info.Size)

			assert.ElementsMatch(t, []string{prefix + "a", prefix + "sub/b"}, listKeys(t, s, prefix))
			if name == "s3" {
				head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s3Bucket), Key: aws.String(prefix + "a")})
				require.NoError(t, err)
				assert.Equal(t, types.ServerSideEncryptionAes256, head.ServerSideEncryption)
			}

			bad := in([]byte("tampered"))
			bad.SHA256 = sha256.Sum256([]byte("other"))
			require.Error(t, s.Put(ctx, prefix+"bad", bad), "a checksum mismatch must be refused")

			require.NoError(t, s.Delete(ctx, prefix+"a"))
			require.NoError(t, s.Delete(ctx, prefix+"a"), "deleting a missing object succeeds")
			_, _, err = s.Get(ctx, prefix+"a")
			require.ErrorIs(t, err, files.ErrNotFound)
			_, err = s.Stat(ctx, prefix+"a")
			require.ErrorIs(t, err, files.ErrNotFound)
			require.Error(t, s.Put(ctx, "../escape", in(body)))
			require.NoError(t, s.Delete(ctx, prefix+"sub/b"))
		})
	}
}

const s3Bucket = "keel-test"

// s3Store connects to the compose SeaweedFS (profile s3) when it is running.
func s3Store(t *testing.T) (files.Storage, *s3.Client) {
	t.Helper()
	endpoint := os.Getenv("APP_TEST_S3_ENDPOINT") //nolint:forbidigo // test-only: the server comes from the environment
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8333"
	}
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	conn, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(t.Context(), "tcp", host)
	if err != nil {
		t.Logf("S3 contract skipped: nothing listens on %s (start it with docker compose --profile s3 up -d seaweedfs)", endpoint)
		return nil, nil
	}
	_ = conn.Close()                                    // only probing
	s, err := files.NewS3(t.Context(), files.S3Options{ //nolint:gosec // local SeaweedFS accepts any key
		Endpoint: endpoint, Bucket: s3Bucket, Region: "us-east-1", AccessKey: "keel", SecretKey: "keel-local-s3-secret", PathStyle: true,
	})
	require.NoError(t, err)
	return s, createBucket(t, endpoint, s3Bucket)
}

func createBucket(t *testing.T, endpoint, bucket string) *s3.Client {
	t.Helper()
	client := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "keel", SecretAccessKey: "keel-local-s3-secret"}, nil //nolint:gosec // local SeaweedFS accepts any key
		}),
	})
	_, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	var exists interface{ ErrorCode() string }
	if err != nil && (!errors.As(err, &exists) || (exists.ErrorCode() != "BucketAlreadyOwnedByYou" && exists.ErrorCode() != "BucketAlreadyExists")) {
		require.NoError(t, err)
	}
	return client
}

func put(t *testing.T, svc *files.Service, by files.Uploader, body string) files.Receipt {
	t.Helper()
	r, err := svc.Put(t.Context(), files.Upload{Kind: kindNote, Name: "n.txt", Body: strings.NewReader(body), By: by})
	require.NoError(t, err)
	return r
}

func inTx(ctx context.Context, d *db.DB, fn func(ctx context.Context, tx db.Transaction) error) error {
	return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) })
}

func stage(ctx context.Context, t *testing.T, d *db.DB, svc *files.Service, id files.ID, by files.Uploader) files.File {
	t.Helper()
	var f files.File
	require.NoError(t, inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
		var err error
		f, err = svc.Stage(ctx, tx, id, by)
		return err
	}))
	return f
}

var errRollback = errors.New("roll back")

func TestService_OnlyTheUploaderClaimsAFile(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.DB()
		local, _ := newLocal(t)
		svc := newService(t, d, local, nil)
		ctx := t.Context()
		r := put(t, svc, alice, "attach me")
		owner := files.Owner{Type: "notes", ID: uuid.New()}
		stageAs := func(by files.Uploader) error {
			return inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error { _, err := svc.Stage(ctx, tx, r.ID, by); return err })
		}
		attach := func(kind string, owner files.Owner, by files.Uploader) error {
			return inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error { return svc.Attach(ctx, tx, r.ID, kind, owner, by) })
		}

		require.ErrorIs(t, attach(kindNote, owner, alice), files.ErrNotFound, "a pending file must be staged first")
		require.ErrorIs(t, stageAs(bob), files.ErrNotFound, "another principal must not stage an upload")
		require.NoError(t, stageAs(alice))
		require.ErrorIs(t, stageAs(alice), files.ErrNotFound, "a file is staged once")
		require.ErrorIs(t, attach(kindNote, owner, bob), files.ErrNotFound, "another principal must not attach a staged file")
		require.ErrorIs(t, attach(kindAvatar, owner, alice), files.ErrNotFound, "a file of another kind must not attach")
		require.Error(t, attach(kindNote, files.Owner{Type: "notes"}, alice), "an owner needs an id")
		require.NoError(t, attach(kindNote, owner, alice))
		require.ErrorIs(t, attach(kindNote, owner, alice), files.ErrNotFound, "an attached file must not move to another owner")

		other := put(t, svc, bob, "attached by a job")
		stage(ctx, t, d, svc, other.ID, bob)
		require.NoError(t, inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
			return svc.Attach(ctx, tx, other.ID, kindNote, owner, files.SystemUploader)
		}), "the system attaches any staged file")

		var f files.File
		err := inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
			var err error
			if f, err = svc.File(ctx, tx, r.ID); err != nil {
				return err
			}
			assert.Equal(t, &owner, f.Owner)
			assert.Equal(t, alice, f.Uploader)
			if err := svc.Remove(ctx, tx, r.ID); err != nil {
				return err
			}
			return errRollback
		})
		require.ErrorIs(t, err, errRollback)
		_, err = local.Stat(ctx, f.Key)
		require.NoError(t, err, "a rolled back remove must keep the object")

		require.NoError(t, inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error { return svc.Remove(ctx, tx, r.ID) }))
		_, err = local.Stat(ctx, f.Key)
		assert.ErrorIs(t, err, files.ErrNotFound)
	})
}

// ownLayoutKey is a key in the layout the service makes, for objects planted without a row.
func ownLayoutKey(prefix string) string {
	r := strings.ReplaceAll(uuid.NewString(), "-", "")
	return prefix + "f/" + r[:2] + "/" + r[2:4] + "/" + r
}

func plant(t *testing.T, s files.Storage, key string) {
	t.Helper()
	body := []byte("planted")
	require.NoError(t, s.Put(t.Context(), key, files.PutInput{Body: bytes.NewReader(body), Size: int64(len(body)), SHA256: sha256.Sum256(body)}))
}

func TestSweep_RemovesOnlyOldOrphansAndUnclaimedFiles(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		local, dir := newLocal(t)
		svc := newService(t, d, local, nil)
		ctx := t.Context()
		now := clock.Wall(ctx).Now()

		attached := stage(ctx, t, d, svc, put(t, svc, alice, "attached").ID, alice)
		require.NoError(t, inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
			return svc.Attach(ctx, tx, attached.ID, kindNote, files.Owner{Type: "notes", ID: uuid.New()}, alice)
		}))
		staged := stage(ctx, t, d, svc, put(t, svc, alice, "never attached").ID, alice)
		pending := put(t, svc, alice, "never staged")
		for range 3 {
			plant(t, local, ownLayoutKey(""))
		}
		young := ownLayoutKey("")
		plant(t, local, young)
		require.NoError(t, os.Chtimes(filepath.Join(dir, young), now.Add(90*time.Minute), now.Add(90*time.Minute)))
		plant(t, local, "assets/logo")
		plant(t, local, "f/not-ours")

		later := clock.WithWall(ctx, clock.Fixed(now.Add(2*time.Hour)))
		res, err := svc.Sweep(later, files.SweepOptions{MinAge: time.Hour, TTL: time.Hour, Batch: 2})
		require.NoError(t, err)
		assert.Equal(t, files.SweepResult{Orphans: 3, Expired: 2}, res)
		assert.ElementsMatch(t, []string{attached.Key, young, "assets/logo", "f/not-ours"}, listKeys(t, local, ""))

		for _, id := range []files.ID{staged.ID, pending.ID} {
			err = inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error { _, err := svc.File(ctx, tx, id); return err })
			assert.ErrorIs(t, err, files.ErrNotFound)
		}
	})
}

func TestSweep_LeavesAFileBeingStaged(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		local, _ := newLocal(t)
		svc := newService(t, d, local, nil)
		ctx := t.Context()
		r := put(t, svc, alice, "staged while the sweep runs")

		staging, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
				if _, err := svc.Stage(ctx, tx, r.ID, alice); err != nil {
					return err
				}
				close(staging)
				<-release
				return nil
			})
		}()
		<-staging
		later := clock.WithWall(ctx, clock.Fixed(clock.Wall(ctx).Now().Add(2*time.Hour)))
		res, err := svc.Sweep(later, files.SweepOptions{MinAge: time.Hour, TTL: time.Hour})
		close(release)
		require.NoError(t, err)
		require.NoError(t, <-done)
		assert.Equal(t, files.SweepResult{}, res)

		require.NoError(t, inTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
			f, err := svc.File(ctx, tx, r.ID)
			if err == nil {
				assert.Equal(t, files.Staged, f.State)
				_, err = local.Stat(ctx, f.Key)
			}
			return err
		}))
	})
}

func TestS3_EncryptsByDefaultAndPresignsAsAttachment(t *testing.T) {
	var sse string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sse = r.Header.Get("X-Amz-Server-Side-Encryption")
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()
	type appConfig struct {
		Env   config.Env   `env:"ENV"`
		Files files.Config `envPrefix:"FILES_"`
	}
	cfg, err := config.LoadFrom[appConfig]("APP_", []string{
		"APP_ENV=test", "APP_FILES_DRIVER=s3", "APP_FILES_S3_BUCKET=b", "APP_FILES_S3_REGION=us-east-1", "APP_FILES_S3_ENDPOINT=" + srv.URL,
		"APP_FILES_S3_ACCESS_KEY=k", "APP_FILES_S3_SECRET_KEY=local-test-secret-key", "APP_FILES_S3_PATH_STYLE=true",
	})
	require.NoError(t, err)
	store, err := files.Open(t.Context(), cfg.Files)
	require.NoError(t, err)

	body := []byte("x")
	require.NoError(t, store.Put(t.Context(), "f/k", files.PutInput{Body: bytes.NewReader(body), Size: 1, SHA256: sha256.Sum256(body), ContentType: "text/plain"}))
	assert.Equal(t, "AES256", sse)

	link, err := store.(files.Presigner).PresignGet(t.Context(), "f/k", time.Minute, "report.pdf", inspect.TypePDF)
	require.NoError(t, err)
	u, err := url.Parse(link)
	require.NoError(t, err)
	assert.Equal(t, files.ContentDisposition("report.pdf"), u.Query().Get("response-content-disposition"))
	assert.Equal(t, inspect.TypePDF, u.Query().Get("response-content-type"))
}

// presigning is local storage that also presigns, as S3 does.
type presigning struct{ *files.Local }

func (presigning) PresignGet(_ context.Context, key string, _ time.Duration, _, _ string) (string, error) {
	return "https://bucket.example.test/" + key, nil
}

// A presigned link bypasses row-level security and fileshttp, so PublicURL, like Open, serves only a key
// of the context's tenant.
func TestPublicURL_KeepsToTheContextsTenant(t *testing.T) {
	local, _ := newLocal(t)
	svc, err := files.NewService(files.Options{
		Storage: presigning{local}, Inspector: inspect.New(inspect.Limits{}, 1), TempDir: t.TempDir(),
		Tx:       func(context.Context, func(context.Context, db.Transaction) error) error { return errRollback },
		Policies: map[string]files.Policy{kindAvatar: {MaxBytes: 1 << 20, Types: []string{inspect.TypePNG}, Visibility: files.Public, Presign: true}},
	})
	require.NoError(t, err)
	a, b := uuid.New(), uuid.New()
	keyOf := func(tenant uuid.UUID) string {
		r := strings.ReplaceAll(uuid.NewString(), "-", "")
		return "f/" + tenant.String() + "/" + r[:2] + "/" + r[2:4] + "/" + r
	}
	inA := db.WithTenant(t.Context(), a)
	tests := []struct {
		name string
		ctx  context.Context
		key  string
		ok   bool
	}{
		{"its own tenant's file", inA, keyOf(a), true},
		{"another tenant's file", inA, keyOf(b), false},
		{"a tenant's file outside any tenant", t.Context(), keyOf(a), false},
		{"a file without a tenant inside one", inA, ownLayoutKey(""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.PublicURL(tt.ctx, files.File{Kind: kindAvatar, Key: tt.key, Visibility: files.Public}, time.Minute) //nolint:contextcheck // the case's context is the subject
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, files.ErrNotFound)
		})
	}
}
