// Package seal encrypts small secrets at rest (provider tokens, webhook signing secrets) with AES-256-GCM
// under keys derived from a configured key list, newest first, so keys rotate without re-encrypting.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/PuckxPuck/keel/internal/kit/config"
)

const version = 1

var ErrUndecryptable = errors.New("seal: no configured key opens the value")

// Keyring seals with the first key and opens with any.
type Keyring struct {
	aeads []cipher.AEAD
}

// NewKeyring derives one AES-256 key per secret with HKDF-SHA256; purpose separates keyrings built
// from the same secrets.
func NewKeyring(secrets []config.Secret, purpose string) (*Keyring, error) {
	if len(secrets) == 0 {
		return nil, errors.New("seal: at least one key is required")
	}
	k := &Keyring{aeads: make([]cipher.AEAD, 0, len(secrets))}
	for i, s := range secrets {
		if s.Reveal() == "" {
			return nil, fmt.Errorf("seal: key %d is empty", i+1)
		}
		key, err := hkdf.Key(sha256.New, []byte(s.Reveal()), nil, "keel seal v1 "+purpose, 32)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		k.aeads = append(k.aeads, aead)
	}
	return k, nil
}

// Seal binds the ciphertext to aad (such as the row id and column), so a value copied to another row
// does not open.
func (k *Keyring) Seal(plain, aad []byte) []byte {
	aead := k.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce) // crypto/rand.Read never fails
	out := append([]byte{version}, nonce...)
	return aead.Seal(out, nonce, plain, aad)
}

// Open returns the plaintext and whether a key other than the newest opened it (reseal it then).
func (k *Keyring) Open(sealed, aad []byte) ([]byte, bool, error) {
	for i, aead := range k.aeads {
		n := aead.NonceSize()
		if len(sealed) < 1+n || sealed[0] != version {
			return nil, false, ErrUndecryptable
		}
		plain, err := aead.Open(nil, sealed[1:1+n], sealed[1+n:], aad)
		if err == nil {
			return plain, i > 0, nil
		}
	}
	return nil, false, ErrUndecryptable
}
