// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass v0.0.1
// (b9f4b677). Replace with that module once it is public (IGA-5320).

package multipass

// The structs below mirror the JSON_V1 codec in Multipass, which writes keys in
// declaration order and omits empty optionals. Field names and shapes follow
// crates/latchkey-client-sdk/src/secret_types/definitions.rs; Multipass rejects
// unknown keys and nulls, so every optional field carries omitempty.

// Typed is a value that names the Multipass content type it belongs to.
type Typed interface {
	MultipassTypeID() string
}

// PasswordV2 is Multipass's password_v2 value.
type PasswordV2 struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	OTPURL   string `json:"otp_url,omitempty"`
}

func (v PasswordV2) MultipassTypeID() string { return TypePasswordV2 }

// APIKeyV2 is Multipass's api_key_v2 value.
type APIKeyV2 struct {
	KeyValue   string   `json:"key_value"`
	Provider   string   `json:"provider,omitempty"`
	BaseURL    string   `json:"base_url,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	KeyID      string   `json:"key_id,omitempty"`
	HeaderName string   `json:"header_name,omitempty"`
	// ExpiresAt is a date in YYYY-MM-DD form.
	ExpiresAt string `json:"expires_at,omitempty"`
}

func (v APIKeyV2) MultipassTypeID() string { return TypeAPIKeyV2 }

// SSHKey is Multipass's ssh_key value.
type SSHKey struct {
	PrivateKey     string   `json:"private_key"`
	Username       string   `json:"username,omitempty"`
	Passphrase     string   `json:"passphrase,omitempty"`
	PublicKey      string   `json:"public_key,omitempty"`
	Hosts          []string `json:"hosts,omitempty"`
	SSHCertificate string   `json:"ssh_certificate,omitempty"`
}

func (v SSHKey) MultipassTypeID() string { return TypeSSHKey }

// OAuthClientSecretV2 is Multipass's oauth_client_secret_v2 value.
type OAuthClientSecretV2 struct {
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret"`
	TokenEndpointURL string   `json:"token_endpoint_url,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	IssuerURL        string   `json:"issuer_url,omitempty"`
	RedirectURIs     []string `json:"redirect_uri,omitempty"`
	AuthEndpointURL  string   `json:"auth_endpoint_url,omitempty"`
	Audience         string   `json:"audience,omitempty"`
	GrantType        string   `json:"grant_type,omitempty"`
}

func (v OAuthClientSecretV2) MultipassTypeID() string { return TypeOAuthClientSecretV2 }

// Certificate is Multipass's certificate value.
type Certificate struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKey     string `json:"private_key,omitempty"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
}

func (v Certificate) MultipassTypeID() string { return TypeCertificate }
