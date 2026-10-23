package totp

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

const (
	sealVersion = 1
	keyInfo     = "keel mfa totp v1"
)

var errUndecryptable = errors.New("totp: no configured key opens the secret")

// keyring encrypts with the first key and opens with any, newest first, so keys rotate without
// re-enrolling anyone.
type keyring []cipher.AEAD

func newKeyring(secrets []config.Secret) (keyring, error) {
	if len(secrets) == 0 {
		return nil, errors.New("totp: at least one MFA key is required")
	}
	ring := make(keyring, 0, len(secrets))
	for i, s := range secrets {
		if s.Reveal() == "" {
			return nil, fmt.Errorf("totp: MFA key %d is empty", i+1)
		}
		key, err := hkdf.Key(sha256.New, []byte(s.Reveal()), nil, keyInfo, 32)
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
		ring = append(ring, aead)
	}
	return ring, nil
}

// seal binds the ciphertext to aad (the user), so a row copied to another user does not open.
func (k keyring) seal(plain, aad []byte) []byte {
	aead := k[0]
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce) // crypto/rand.Read never fails
	out := append([]byte{sealVersion}, nonce...)
	return aead.Seal(out, nonce, plain, aad)
}

// open returns the plaintext and whether a key other than the newest opened it.
func (k keyring) open(sealed, aad []byte) ([]byte, bool, error) {
	for i, aead := range k {
		n := aead.NonceSize()
		if len(sealed) < 1+n || sealed[0] != sealVersion {
			return nil, false, errUndecryptable
		}
		plain, err := aead.Open(nil, sealed[1:1+n], sealed[1+n:], aad)
		if err == nil {
			return plain, i > 0, nil
		}
	}
	return nil, false, errUndecryptable
}
