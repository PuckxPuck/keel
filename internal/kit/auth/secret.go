package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// SecretBytes is the entropy of session tokens, link tokens and device secrets.
const SecretBytes = 32

var secretEncoding = base64.RawURLEncoding

// SecretLen is the length of an encoded secret.
var SecretLen = secretEncoding.EncodedLen(SecretBytes)

var ErrMalformedSecret = errors.New("auth: malformed secret")

// NewSecret returns a random secret for the client and its SHA-256 for storage. The secret has 256
// bits of entropy, so a fast hash is enough; nothing that leaks from the database is usable.
func NewSecret() (raw string, hash []byte) {
	b := make([]byte, SecretBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	raw = secretEncoding.EncodeToString(b)
	return raw, Hash(raw)
}

// HashSecret checks raw has the shape NewSecret makes and returns its hash.
func HashSecret(raw string) ([]byte, error) {
	if len(raw) != SecretLen {
		return nil, ErrMalformedSecret
	}
	b, err := secretEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != SecretBytes {
		return nil, ErrMalformedSecret
	}
	return Hash(raw), nil
}

// Hash is the stored form of a secret.
func Hash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
