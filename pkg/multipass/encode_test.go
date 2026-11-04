// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass v0.0.1 (b9f4b677).
// Replace with that module once it is public (IGA-5320).

package multipass

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJSONKeys pins the exact bytes each type serializes to. Multipass's
// JSON_V1 codec writes keys in declaration order and omits empty optionals, so
// both the key names and their absence for unset fields are part of the format.
func TestJSONKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Typed
		want  string
	}{
		{
			name: TypePasswordV2,
			value: PasswordV2{
				Username: "alice",
				Password: "hunter2",
				URL:      "https://example.test",
				OTPURL:   "otpauth://totp/example:alice?secret=X",
			},
			want: `{"username":"alice","password":"hunter2","url":"https://example.test","otp_url":"otpauth://totp/example:alice?secret=X"}`,
		},
		{
			name:  TypePasswordV2 + " required only",
			value: PasswordV2{Password: "hunter2"},
			want:  `{"password":"hunter2"}`,
		},
		{
			name: TypeAPIKeyV2,
			value: APIKeyV2{
				KeyValue:   "dd-key",
				Provider:   "datadog",
				BaseURL:    "https://api.datadoghq.com",
				Scopes:     []string{"read"},
				KeyID:      "key-id",
				HeaderName: "DD-API-KEY",
				ExpiresAt:  "2027-01-01",
			},
			want: `{"key_value":"dd-key","provider":"datadog","base_url":"https://api.datadoghq.com","scopes":["read"],"key_id":"key-id","header_name":"DD-API-KEY","expires_at":"2027-01-01"}`,
		},
		{
			name:  TypeAPIKeyV2 + " required only",
			value: APIKeyV2{KeyValue: "dd-key"},
			want:  `{"key_value":"dd-key"}`,
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
			want: `{"private_key":"private","username":"ubuntu","passphrase":"passphrase","public_key":"public","hosts":["host.example.test"],"ssh_certificate":"certificate"}`,
		},
		{
			name:  TypeSSHKey + " required only",
			value: SSHKey{PrivateKey: "private"},
			want:  `{"private_key":"private"}`,
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
			want: `{"client_id":"client-id","client_secret":"client-secret",` +
				`"token_endpoint_url":"https://example.test/token","scopes":["read"],` +
				`"issuer_url":"https://example.test","redirect_uri":["https://example.test/callback"],` +
				`"auth_endpoint_url":"https://example.test/authorize",` +
				`"audience":"audience","grant_type":"client_credentials"}`,
		},
		{
			name:  TypeOAuthClientSecretV2 + " required only",
			value: OAuthClientSecretV2{ClientID: "client-id", ClientSecret: "client-secret"},
			want:  `{"client_id":"client-id","client_secret":"client-secret"}`,
		},
		{
			name: TypeCertificate,
			value: Certificate{
				CertificatePEM: "certificate",
				PrivateKey:     "private",
				ChainPEM:       "chain",
				Passphrase:     "passphrase",
			},
			want: `{"certificate_pem":"certificate","private_key":"private","chain_pem":"chain","passphrase":"passphrase"}`,
		},
		{
			name:  TypeCertificate + " required only",
			value: Certificate{CertificatePEM: "certificate"},
			want:  `{"certificate_pem":"certificate"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.value)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(encoded))
		})
	}
}

func TestContentTypeNamespace(t *testing.T) {
	// A caller distinguishes Multipass types from another vendor's by prefix,
	// so every type ContentType builds must carry it and others must not.
	require.Equal(t, "application/vnd.multipass.", ContentTypePrefix)
	for _, id := range []string{TypePasswordV2, TypeAPIKeyV2, TypeSSHKey, TypeOAuthClientSecretV2, TypeCertificate} {
		require.True(t, strings.HasPrefix(ContentType(id), ContentTypePrefix), ContentType(id))
	}
	require.False(t, strings.HasPrefix("application/vnd.other.api_key_v2+json", ContentTypePrefix))
}

func TestContentTypeRoundTrip(t *testing.T) {
	for _, id := range []string{TypePasswordV2, TypeAPIKeyV2, TypeSSHKey, TypeOAuthClientSecretV2, TypeCertificate, "future_type"} {
		require.Equal(t, "application/vnd.multipass."+id+"+json", ContentType(id))
		actual, ok := TypeIDFromContentType(ContentType(id))
		require.True(t, ok)
		require.Equal(t, id, actual)
	}
}

func TestTypeIDFromContentTypeRejectsOtherTypes(t *testing.T) {
	for _, contentType := range []string{
		"",
		"application/json",
		"application/vnd.multipass.api_key_v2",
		"application/vnd.multipass.+json",
		"application/vnd.multipass./+json",
		"application/vnd.other.api_key_v2+json",
	} {
		_, ok := TypeIDFromContentType(contentType)
		require.False(t, ok, contentType)
	}
}

func TestOutputFieldDeclaresTheType(t *testing.T) {
	field := OutputField("api_key", TypeAPIKeyV2)
	require.Equal(t, "api_key", field.GetName())
	require.Equal(t, "application/vnd.multipass.api_key_v2+json", field.GetContentType())
	require.Equal(t, []string{"credential", "api_key", "multipass", "api_key_v2"}, field.GetTags())
	require.True(t, field.GetIsSecret())
	require.True(t, field.HasStringField(), "content_type is only valid on the string-shaped fields")
	require.NoError(t, field.Validate())
}

func TestTags(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want []string
	}{
		{TypeAPIKeyV2, []string{"credential", "api_key", "multipass", "api_key_v2"}},
		{TypePasswordV2, []string{"credential", "password", "multipass", "password_v2"}},
		{TypeSSHKey, []string{"credential", "ssh_key", "multipass", "ssh_key"}},
		{TypeOAuthClientSecretV2, []string{"credential", "oauth_client_secret", "multipass", "oauth_client_secret_v2"}},
		{TypeCertificate, []string{"credential", "certificate", "multipass", "certificate"}},
		// A type with no kind in field's vocabulary carries only the storage
		// tag. These are text-coded types a connector does not emit, plus one
		// ID that is not a Multipass type at all.
		{"hotp", []string{"credential", "multipass", "hotp"}},
		{"note", []string{"credential", "multipass", "note"}},
		{"generic", []string{"credential", "multipass", "generic"}},
		{"future_type", []string{"credential", "multipass", "future_type"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			require.Equal(t, tc.want, Tags(tc.id))
		})
	}
}

func TestPlaintextSetsSchema(t *testing.T) {
	plaintext, err := Plaintext("api_key", APIKeyV2{KeyValue: "dd-key"})
	require.NoError(t, err)
	require.Equal(t, "api_key", plaintext.GetName())
	require.Equal(t, "application/vnd.multipass.api_key_v2+json", plaintext.GetSchema())
	require.JSONEq(t, `{"key_value":"dd-key"}`, string(plaintext.GetBytes()))
}

// unencodable is a Typed whose JSON encoder fails, so Plaintext's error path is
// exercised through the interface a caller supplies.
type unencodable struct{}

func (unencodable) MultipassTypeID() string { return TypeAPIKeyV2 }

func (unencodable) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cannot encode")
}

func TestPlaintextWrapsEncodeError(t *testing.T) {
	_, err := Plaintext("api_key", unencodable{})
	require.Error(t, err)
	require.ErrorContains(t, err, "secret: encode api_key_v2: ")
	require.ErrorContains(t, err, "cannot encode")
}
