package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/money"
)

type credentials struct {
	Login    string `json:"login"`
	Password string `json:"password" audit:"redact"`
	Hash     []byte `json:"hash" audit:"-"`
}

type account struct {
	credentials
	Name     string         `json:"name"`
	Token    *string        `json:"token,omitempty" audit:"redact"`
	Note     string         `json:"note,omitempty"`
	Internal string         `json:"-"`
	Keys     []credentials  `json:"keys"`
	ByName   map[string]any `json:"byName"`
	Seen     time.Time      `json:"seen"`
	private  string
}

// wrapped has its own marshalling that would print the secret; its fields are walked anyway.
type wrapped struct {
	Login    string `json:"login"`
	Password string `json:"password" audit:"redact"`
}

func (w wrapped) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"all": w.Login + w.Password})
}

// bearer prints its value when marshalled and says nothing about audit: it is opaque.
type bearer string

func (t bearer) MarshalText() ([]byte, error) { return []byte(t), nil }

// masked chooses what the audit log shows of it.
type masked string

func (m masked) MarshalText() ([]byte, error) { return []byte(m), nil }
func (m masked) AuditValue() any              { return "****" + string(m[len(m)-2:]) }

type tenantTag struct{}

const someID = "0192f5a0-0000-7000-8000-000000000001"

func TestMarshal_AppliesAuditTags(t *testing.T) {
	token := "t0ken"
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil stays null", nil, ""},
		{
			"redacts and drops tagged fields, embedded and nested",
			account{
				credentials: credentials{Login: "ann", Password: "hunter2", Hash: []byte{1}},
				Name:        "Ann", Token: &token, Internal: "x", private: "y",
				Keys:   []credentials{{Login: "k", Password: "p"}},
				ByName: map[string]any{"b": 2, "a": credentials{Password: "q"}},
				Seen:   time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC),
			},
			`{"byName":{"a":{"login":"","password":"[redacted]"},"b":2},"keys":[{"login":"k","password":"[redacted]"}],` +
				`"login":"ann","name":"Ann","password":"[redacted]","seen":"2026-10-22T09:00:00Z","token":"[redacted]"}`,
		},
		{"a pointer to a struct is followed", &credentials{Login: "bo", Password: "pw"}, `{"login":"bo","password":"[redacted]"}`},
		{"a struct's own marshalling does not hide its tags", wrapped{Login: "ann", Password: "hunter2"}, `{"login":"ann","password":"[redacted]"}`},
		{
			"opaque marshallers are not printed, redactable ones show what they choose",
			map[string]any{"t": bearer("s3cret"), "m": masked("4111111111111111")},
			`{"m":"****11","t":"[opaque]"}`,
		},
		{
			"map keys are stringified and sensitive ones redacted",
			map[any]any{7: "seven", "apiKey": "k", "note": map[int]bool{1: true}},
			`{"7":"seven","apiKey":"[redacted]","note":{"1":true}}`,
		},
		{
			"known safe types keep their own form",
			map[string]any{"id": ids.FromUUID[tenantTag](uuid.MustParse(someID)), "price": money.Amount{Minor: 1250, Currency: "USD"}},
			`{"id":"` + someID + `","price":{"amount":1250,"currency":"USD"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshal(tt.in)
			require.NoError(t, err)
			if tt.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, *got)
		})
	}
}

func TestCanonical_WritesNumbersAsExactDecimals(t *testing.T) {
	for in, want := range map[string]string{
		`[1e21, 1E2, 100.0, -0, -12.50]`: `[1000000000000000000000,100,100,0,-12.5]`,
		`{"b": 1.5e-7, "a": 0.1}`:        `{"a":0.1,"b":0.00000015}`,
		`[18446744073709551615]`:         `[18446744073709551615]`,
	} {
		got, err := canonical([]byte(in))
		require.NoError(t, err)
		assert.Equal(t, want, got, in)
	}
}
