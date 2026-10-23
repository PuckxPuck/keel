// Package passkeytest is a software passkey for tests: one P-256 key with "none" attestation that
// answers the options a ceremony's Begin returned.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/stretchr/testify/require"
)

const (
	FlagUP = 0x01
	FlagUV = 0x04
	flagAT = 0x40
)

type Authenticator struct {
	rpID   string
	origin string
	key    *ecdsa.PrivateKey
	credID []byte
	// UserHandle is what a sign-in answers as the user; registration sets it from the options.
	UserHandle []byte
}

func New(t testing.TB, rpID, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{rpID: rpID, origin: origin, key: key, credID: id}
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func parse(t testing.TB, raw []byte) options {
	t.Helper()
	var o options
	require.NoError(t, json.Unmarshal(raw, &o))
	return o
}

// Register answers navigator.credentials.create with the options Begin returned.
func (a *Authenticator) Register(t testing.TB, opts []byte) []byte {
	t.Helper()
	o := parse(t, opts)
	handle, err := base64.RawURLEncoding.DecodeString(o.PublicKey.User.ID)
	require.NoError(t, err)
	a.UserHandle = handle
	point, err := a.key.PublicKey.Bytes()
	require.NoError(t, err)
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]})
	require.NoError(t, err)
	attested := make([]byte, 16, 16+2+len(a.credID)+len(cose))
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID))) //nolint:gosec // 32 bytes
	attested = append(append(attested, a.credID...), cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(FlagUP|FlagUV|flagAT, 0, attested)})
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(a.clientData("webauthn.create", o.PublicKey.Challenge)), "attestationObject": b64(att)},
	})
	return body
}

// Assert answers navigator.credentials.get with the options Begin returned, the flags and sign count.
func (a *Authenticator) Assert(t testing.TB, opts []byte, flags byte, count uint32) []byte {
	t.Helper()
	data := a.authData(flags, count, nil)
	cdj := a.clientData("webauthn.get", parse(t, opts).PublicKey.Challenge)
	sum := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, data...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(cdj), "authenticatorData": b64(data), "signature": b64(sig), "userHandle": b64(a.UserHandle)},
	})
	return body
}

func (a *Authenticator) authData(flags byte, count uint32, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func (a *Authenticator) clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
