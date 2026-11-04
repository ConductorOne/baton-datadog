// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass at b9f4b677.
// Replace with that module once it is public (<TICKET>).

package multipass

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Typed
	}{
		{
			name: TypePasswordV2,
			value: PasswordV2{
				Username: "alice",
				Password: "hunter2",
				URL:      "https://example.test",
				OTPURL:   "otpauth://totp/example:alice?secret=X",
			},
		},
		{
			name: TypeAPIKeyV2,
			value: APIKeyV2{
				KeyValue:   "dd-key",
				Provider:   "datadog",
				BaseURL:    "https://api.datadoghq.com",
				Scopes:     []string{"read", "write"},
				KeyID:      "key-id",
				HeaderName: "DD-API-KEY",
				ExpiresAt:  "2027-01-01",
			},
		},
		{
			name: TypeSSHKey,
			value: SSHKey{
				PrivateKey:     "private",
				Username:       "ubuntu",
				Passphrase:     "passphrase",
				PublicKey:      "public",
				Hosts:          []string{"host.example.test"},
				SSHCertificate: "certificate",
			},
		},
		{
			name: TypeOAuthClientSecretV2,
			value: OAuthClientSecretV2{ //nolint:gosec // Test fixture, not a credential value.
				ClientID:         "client-id",
				ClientSecret:     "client-secret",
				TokenEndpointURL: "https://example.test/token",
				Scopes:           []string{"read"},
				IssuerURL:        "https://example.test",
				RedirectURIs:     []string{"https://example.test/callback"},
				AuthEndpointURL:  "https://example.test/authorize",
				Audience:         "audience",
				GrantType:        "client_credentials",
			},
		},
		{
			name:  TypeCertificate,
			value: Certificate{CertificatePEM: "certificate", PrivateKey: "private", ChainPEM: "chain", Passphrase: "passphrase"},
		},
		{
			// The required-only form must decode too: every optional key absent.
			name:  TypeAPIKeyV2 + " required only",
			value: APIKeyV2{KeyValue: "dd-key"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := Plaintext("credential", tc.value)
			require.NoError(t, err)

			decoded, err := Decode(plaintext.GetSchema(), plaintext.GetBytes())
			require.NoError(t, err)
			require.Equal(t, tc.value, decoded)
		})
	}
}

func TestDecodeRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
		data string
		want string
	}{
		{
			name: "unknown key",
			id:   TypeAPIKeyV2,
			data: `{"key_value":"k","unexpected":"v"}`,
			want: `unknown key "unexpected"`,
		},
		{
			name: "duplicate key",
			id:   TypeAPIKeyV2,
			data: `{"key_value":"first","key_value":"second"}`,
			want: `duplicate key "key_value"`,
		},
		{
			name: "null scalar",
			id:   TypeAPIKeyV2,
			data: `{"key_value":null}`,
			want: `null value for "key_value"`,
		},
		{
			name: "null optional",
			id:   TypeAPIKeyV2,
			data: `{"key_value":"k","provider":null}`,
			want: `null value for "provider"`,
		},
		{
			name: "null in list",
			id:   TypeAPIKeyV2,
			data: `{"key_value":"k","scopes":["read",null]}`,
			want: `null value in "scopes"`,
		},
		{
			name: "missing required",
			id:   TypeAPIKeyV2,
			data: `{"provider":"datadog"}`,
			want: `missing required key "key_value"`,
		},
		{
			name: "missing both required",
			id:   TypeOAuthClientSecretV2,
			data: `{"scopes":["read"]}`,
			want: `missing required key "client_id"`,
		},
		{
			name: "not an object",
			id:   TypeAPIKeyV2,
			data: `["key_value"]`,
			want: `not a JSON object`,
		},
		{
			name: "invalid JSON",
			id:   TypeAPIKeyV2,
			data: `{"key_value":`,
			want: `invalid JSON`,
		},
		{
			name: "invalid UTF-8",
			id:   TypeAPIKeyV2,
			data: "{\"key_value\":\"\xff\"}",
			want: `not valid UTF-8`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(ContentType(tc.id), []byte(tc.data))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.want)
			// The type ID travels with the error, so a caller knows which
			// credential failed.
			require.ErrorContains(t, err, tc.id)
		})
	}
}

func TestDecodeUnknownContentType(t *testing.T) {
	for _, contentType := range []string{
		"application/json",
		"",
		"application/vnd.other.api_key_v2+json",
		// A well-formed Multipass MIME for an ID this package does not model.
		ContentType("future_type"),
		ContentType("hotp"),
	} {
		_, err := Decode(contentType, []byte(`{}`))
		require.ErrorIs(t, err, ErrUnknownType, contentType)
	}
}

func TestDecodeAsWrongType(t *testing.T) {
	_, err := DecodeAs[SSHKey]([]byte(`{"key_value":"k"}`))
	require.Error(t, err)
	require.ErrorContains(t, err, TypeSSHKey)
	require.ErrorContains(t, err, `unknown key "key_value"`)
}

func TestDecodeAsRoundTrip(t *testing.T) {
	decoded, err := DecodeAs[APIKeyV2]([]byte(`{"key_value":"dd-key","scopes":["read"]}`))
	require.NoError(t, err)
	require.Equal(t, APIKeyV2{KeyValue: "dd-key", Scopes: []string{"read"}}, decoded)
}

func TestDecodeAsReportsTypeErrors(t *testing.T) {
	_, err := DecodeAs[APIKeyV2]([]byte(`{"key_value":42}`))
	require.Error(t, err)
	require.ErrorContains(t, err, TypeAPIKeyV2)
}

func TestDecodeEmptyDocument(t *testing.T) {
	_, err := Decode(ContentType(TypeAPIKeyV2), nil)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrUnknownType))
	require.ErrorContains(t, err, `invalid JSON`)
}
