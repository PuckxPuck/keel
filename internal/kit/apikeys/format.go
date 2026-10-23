package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/big"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	base62       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	crockford    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	secretBytes  = 32
	secretLen    = 43 // 62^43 > 2^256
	checksumLen  = 6  // 62^6 > 2^32
	idLen        = 26 // 128 bits in Crockford base32
	maxKeyLength = 128
	EnvLive      = "live"
	EnvTest      = "test"
)

// ErrMalformed is a string that is not a key of this app and environment, or fails its checksum.
var ErrMalformed = errors.New("apikeys: malformed key")

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

// ValidPrefix is true for a prefix the format allows: 2 to 16 lower case letters and digits.
func ValidPrefix(p string) bool { return prefixPattern.MatchString(p) }

// Format is the key shape of one app in one environment: <prefix>_<env>_<id>_<secret><checksum>.
type Format struct {
	Prefix string
	Env    string
}

func (f Format) head() string { return f.Prefix + "_" + f.Env + "_" }

// newKey makes a key for id and returns it with the SHA-256 of its secret.
func (f Format) newKey(id uuid.UUID) (string, []byte) {
	b := make([]byte, secretBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	secret := encodeBase62(b, secretLen)
	body := f.head() + encodeID(id) + "_" + secret
	return body + checksum(body), hashSecret(secret)
}

// Parse checks the shape and checksum of raw without touching the database and returns the key's id
// and the hash of its secret.
func (f Format) Parse(raw string) (uuid.UUID, []byte, error) {
	head := f.head()
	rest, ok := strings.CutPrefix(raw, head)
	if !ok || len(raw) > maxKeyLength || len(rest) != idLen+1+secretLen+checksumLen || rest[idLen] != '_' {
		return uuid.Nil, nil, ErrMalformed
	}
	body, sum := raw[:len(raw)-checksumLen], raw[len(raw)-checksumLen:]
	if checksum(body) != sum {
		return uuid.Nil, nil, ErrMalformed
	}
	id, ok := decodeID(rest[:idLen])
	secret := rest[idLen+1 : idLen+1+secretLen]
	if !ok || id == uuid.Nil || strings.Trim(secret, base62) != "" {
		return uuid.Nil, nil, ErrMalformed
	}
	return id, hashSecret(secret), nil
}

// hint is what the app shows of a key after creation: its prefix and last four characters.
func (f Format) hint(key string) string { return f.head() + "..." + key[len(key)-4:] }

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func checksum(body string) string {
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE([]byte(body)))
	return encodeBase62(sum[:], checksumLen)
}

// encodeBase62 writes b as a big-endian number in base62, left-padded with zeros to width.
func encodeBase62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(int64(len(base62)))
	out := make([]byte, width)
	mod := new(big.Int)
	for i := width - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = base62[mod.Int64()]
	}
	return string(out)
}

func encodeID(id uuid.UUID) string {
	n := new(big.Int).SetBytes(id[:])
	out := make([]byte, idLen)
	mask := big.NewInt(31)
	digit := new(big.Int)
	for i := idLen - 1; i >= 0; i-- {
		out[i] = crockford[digit.And(n, mask).Int64()]
		n.Rsh(n, 5)
	}
	return string(out)
}

// decodeID reads the canonical form only: upper case, and a first digit that keeps it within 128 bits.
func decodeID(s string) (uuid.UUID, bool) {
	if len(s) != idLen || s[0] > '7' {
		return uuid.Nil, false
	}
	n := new(big.Int)
	for i := range len(s) {
		d := strings.IndexByte(crockford, s[i])
		if d < 0 {
			return uuid.Nil, false
		}
		n.Lsh(n, 5).Or(n, big.NewInt(int64(d)))
	}
	var id uuid.UUID
	n.FillBytes(id[:])
	return id, true
}
