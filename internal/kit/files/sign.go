package files

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	minSignerKey = 32
	// MaxLinkTTL caps how long a public link lives.
	MaxLinkTTL = 7 * 24 * time.Hour
	maxExpires = 20
)

var sigLen = base64.RawURLEncoding.EncodedLen(sha256.Size)

// URLSigner makes and checks expiring links to public files with HMAC-SHA256 over the file id, the
// expiry and, under tenancy, the file's tenant (the download needs it to read the row).
// The first key signs and every key verifies, so the session keys rotate the same way here.
type URLSigner struct {
	base string
	keys [][]byte
}

// NewURLSigner signs links under base, the absolute URL fileshttp.Public is mounted at.
func NewURLSigner(base string, keys ...[]byte) (*URLSigner, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("files: signer base must be an absolute http(s) URL")
	}
	if len(keys) == 0 {
		return nil, errors.New("files: a signer needs at least one key")
	}
	for _, k := range keys {
		if len(k) < minSignerKey {
			return nil, fmt.Errorf("files: signer keys must be at least %d bytes", minSignerKey)
		}
	}
	return &URLSigner{base: strings.TrimSuffix(base, "/"), keys: keys}, nil
}

// URL is a link to the file that expires ttl after now; ttl must be positive and at most MaxLinkTTL.
// tenant is the file's tenant, uuid.Nil without tenancy.
func (s *URLSigner) URL(id ID, tenant uuid.UUID, now time.Time, ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > MaxLinkTTL {
		return "", fmt.Errorf("files: link lifetime must be positive and at most %s", MaxLinkTTL)
	}
	exp := strconv.FormatInt(now.Add(ttl).Unix(), 10)
	q := url.Values{"expires": {exp}, "sig": {base64.RawURLEncoding.EncodeToString(s.mac(s.keys[0], id, tenantParam(tenant), exp))}}
	if tenant != uuid.Nil {
		q.Set("tenant", tenant.String())
	}
	return s.base + "/" + id.String() + "?" + q.Encode(), nil
}

func tenantParam(t uuid.UUID) string {
	if t == uuid.Nil {
		return ""
	}
	return t.String()
}

// Verify checks a link's expiry and signature and returns the tenant it was signed for (uuid.Nil
// without one); every failure is ErrBadSignature.
func (s *URLSigner) Verify(id ID, tenant, expires, sig string, now time.Time) (uuid.UUID, error) {
	t := uuid.Nil
	if tenant != "" {
		parsed, err := uuid.Parse(tenant)
		if err != nil || parsed == uuid.Nil || parsed.String() != tenant {
			return uuid.Nil, ErrBadSignature
		}
		t = parsed
	}
	return t, s.verify(id, tenant, expires, sig, now)
}

func (s *URLSigner) verify(id ID, tenant, expires, sig string, now time.Time) error {
	if len(expires) > maxExpires || len(sig) != sigLen {
		return ErrBadSignature
	}
	exp, err := strconv.ParseInt(expires, 10, 64)
	if err != nil || now.Unix() > exp || exp-now.Unix() > int64(MaxLinkTTL/time.Second) {
		return ErrBadSignature
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrBadSignature
	}
	ok := false
	for _, k := range s.keys {
		ok = hmac.Equal(got, s.mac(k, id, tenant, expires)) || ok
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}

func (s *URLSigner) mac(key []byte, id ID, tenant, expires string) []byte {
	h := hmac.New(sha256.New, key)
	msg := "keel-files-v1\x00" + id.String() + "\x00" + expires
	if tenant != "" {
		msg += "\x00tenant\x00" + tenant
	}
	h.Write([]byte(msg))
	return h.Sum(nil)
}
