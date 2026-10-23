// Package password hashes and checks passwords: argon2id with configured parameters, bounded
// verification, legacy bcrypt, a concurrency cap, the NIST length and common-password policy, and
// failure throttling for sign-in.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"

	"github.com/PuckxPuck/keel/internal/kit/auth"
)

// Params are argon2id's cost: Memory in KiB, Time passes, Threads lanes.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// Configuration bounds. Stored hashes are held to tighter ones relative to the configured parameters
// (Hasher.within), so a tampered row cannot make the server allocate or spin far beyond its own cost.
const (
	maxMemory       = 1 << 20 // 1 GiB in KiB
	maxTime         = 10
	maxThreads      = 16
	maxStoredMemory = 256 << 10 // 256 MiB in KiB
	maxStoredLanes  = 4
	minSaltLen      = 8
	maxSaltLen      = 64
	minKeyLen       = 16
	maxKeyLen       = 64
	saltLen         = 16
	keyLen          = 32
	maxBcryptCost   = 15
	busyWait        = time.Second
)

// The longest password accepted, in characters and in bytes; the API schema uses the same.
const (
	MaxChars = 128
	MaxBytes = 512
)

// TooLong is true for a password over MaxChars characters or MaxBytes bytes.
func TooLong(plain string) bool {
	return len(plain) > MaxBytes || utf8.RuneCountInString(plain) > MaxChars
}

// normalise is NFKC (NIST SP 800-63B-4), so the same password typed on two keyboards hashes alike.
func normalise(plain string) []byte { return []byte(norm.NFKC.String(plain)) }

var b64 = base64.RawStdEncoding

func ParseParams(s string) (Params, error) {
	var p Params
	seen := map[string]bool{}
	for part := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil || seen[k] {
			return Params{}, fmt.Errorf("argon2 parameters %q must look like m=19456,t=2,p=1", s)
		}
		seen[k] = true
		switch k {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n > maxThreads {
				return Params{}, fmt.Errorf("argon2 parallelism must be at most %d", maxThreads)
			}
			p.Threads = uint8(n)
		default:
			return Params{}, fmt.Errorf("argon2 parameters %q must look like m=19456,t=2,p=1", s)
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] {
		return Params{}, fmt.Errorf("argon2 parameters %q need m, t and p", s)
	}
	return p, p.check()
}

func (p *Params) UnmarshalText(text []byte) error {
	parsed, err := ParseParams(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

func (p Params) String() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Time, p.Threads)
}

func (p Params) check() error {
	switch {
	case p.Threads < 1 || p.Threads > maxThreads:
		return fmt.Errorf("argon2 parallelism must be 1 to %d", maxThreads)
	case p.Time < 1 || p.Time > maxTime:
		return fmt.Errorf("argon2 time must be 1 to %d", maxTime)
	case p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory:
		return errors.New("argon2 memory must be at least 8 KiB per lane and at most 1 GiB")
	}
	return nil
}

var (
	ErrMalformedHash = errors.New("password: malformed hash")
	ErrOutOfBounds   = errors.New("password: stored hash parameters are outside the bounds for the configured ones")
	// ErrBusy is every hashing slot taken for longer than a short wait: 429 with Retry-After.
	ErrBusy = &auth.ThrottledError{RetryAfter: time.Second}
)

// Hasher hashes with the configured parameters and verifies argon2id and legacy bcrypt hashes. At most
// maxConcurrent hashes run at once.
type Hasher struct {
	params Params
	slots  chan struct{}
	dummy  string
}

func NewHasher(params Params, maxConcurrent int) (*Hasher, error) {
	if err := params.check(); err != nil {
		return nil, err
	}
	if maxConcurrent < 1 {
		return nil, errors.New("password: at least one concurrent hash")
	}
	h := &Hasher{params: params, slots: make(chan struct{}, maxConcurrent)}
	h.dummy = h.encode(randomBytes(saltLen), []byte("not a password"))
	return h, nil
}

// DummyHash has the current parameters; verifying against it makes an unknown account cost what a
// known one does.
func (h *Hasher) DummyHash() string { return h.dummy }

func (h *Hasher) Hash(ctx context.Context, plain string) (string, error) {
	if TooLong(plain) {
		return "", errors.New("password: longer than the maximum")
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return h.encode(randomBytes(saltLen), normalise(plain)), nil
}

func (h *Hasher) encode(salt, plain []byte) string {
	p := h.params
	key := argon2.IDKey(plain, salt, p.Time, p.Memory, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// within holds a stored hash to at most four times the configured memory (and 256 MiB, unless the
// configured memory is higher), twice the configured time plus one, and four lanes.
func (h *Hasher) within(p Params) bool {
	memory := max(h.params.Memory, min(4*h.params.Memory, maxStoredMemory))
	return p.Memory <= memory && p.Time <= 2*h.params.Time+1 && p.Threads <= max(maxStoredLanes, h.params.Threads)
}

// Verify checks plain against an argon2id or bcrypt hash. rehash is true after a match whose hash is
// bcrypt or has other parameters than the configured ones. Every failure that skipped the argon2id
// work at configured cost (a password over the maximum, a malformed or out-of-bounds hash, a bcrypt
// mismatch) runs one dummy verification, so it takes about as long as a wrong password.
func (h *Hasher) Verify(ctx context.Context, encoded, plain string) (ok, rehash bool, err error) {
	if TooLong(plain) {
		return false, false, h.dummyVerify(ctx)
	}
	if isBcrypt(encoded) {
		ok, err := h.verifyBcrypt(ctx, encoded, plain)
		switch {
		case errors.Is(err, ErrMalformedHash):
			err = errors.Join(err, h.dummyVerify(ctx))
		case err == nil && !ok:
			err = h.dummyVerify(ctx)
		}
		return ok, ok, err
	}
	p, salt, key, err := decode(encoded)
	if err == nil && !h.within(p) {
		err = ErrOutOfBounds
	}
	if err != nil {
		return false, false, errors.Join(err, h.dummyVerify(ctx))
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return false, false, err
	}
	defer release()
	got := argon2.IDKey(normalise(plain), salt, p.Time, p.Memory, p.Threads, uint32(len(key))) //nolint:gosec // decode bounds the key to 16..64 bytes
	ok = subtle.ConstantTimeCompare(got, key) == 1
	return ok, ok && (p != h.params || len(salt) != saltLen || len(key) != keyLen), nil
}

// verifyBcrypt tries the input as typed, then normalised: ported hashes were made from raw input.
func (h *Hasher) verifyBcrypt(ctx context.Context, encoded, plain string) (bool, error) {
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil || cost > maxBcryptCost {
		return false, ErrMalformedHash
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if bcrypt.CompareHashAndPassword([]byte(encoded), []byte(plain)) == nil {
		return true, nil
	}
	if n := normalise(plain); string(n) != plain {
		return bcrypt.CompareHashAndPassword([]byte(encoded), n) == nil, nil
	}
	return false, nil
}

func (h *Hasher) dummyVerify(ctx context.Context) error {
	_, salt, key, err := decode(h.dummy)
	if err != nil {
		return err
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	p := h.params
	_ = argon2.IDKey([]byte("not the password"), salt, p.Time, p.Memory, p.Threads, uint32(len(key))) //nolint:gosec // decode bounds the key to 16..64 bytes
	return nil
}

// NeedsRehash is true when encoded is not argon2id with the configured parameters.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, salt, key, err := decode(encoded)
	return err != nil || p != h.params || len(salt) != saltLen || len(key) != keyLen
}

func (h *Hasher) acquire(ctx context.Context) (func(), error) {
	t := time.NewTimer(busyWait)
	defer t.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func isBcrypt(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// decode parses a PHC argon2id string and refuses parameters outside the bounds.
func decode(encoded string) (Params, []byte, []byte, error) {
	if len(encoded) > 256 {
		return Params{}, nil, nil, ErrMalformedHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrMalformedHash
	}
	p, err := ParseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	salt, err := b64.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return Params{}, nil, nil, ErrMalformedHash
	}
	key, err := b64.Strict().DecodeString(parts[5])
	if err != nil || len(key) < minKeyLen || len(key) > maxKeyLen {
		return Params{}, nil, nil, ErrMalformedHash
	}
	return p, salt, key, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
}
