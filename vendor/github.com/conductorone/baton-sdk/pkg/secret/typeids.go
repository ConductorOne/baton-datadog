package secret

import "strings"

// Content type IDs, matching content_type in Multipass's
// crates/latchkey-client-sdk/src/secret_types/definitions.rs.
const (
	TypePasswordV2          = "password_v2"
	TypeAPIKeyV2            = "api_key_v2" //nolint:gosec // Content type ID, not a credential.
	TypeSSHKey              = "ssh_key"
	TypeOAuthClientSecretV2 = "oauth_client_secret_v2" //nolint:gosec // Content type ID, not a credential.
	TypeCertificate         = "certificate"
)

const contentTypePrefix = "application/vnd.multipass."
const contentTypeSuffix = "+json"

// ContentType returns the MIME type that carries a value of the given type.
func ContentType(id string) string {
	return contentTypePrefix + id + contentTypeSuffix
}

// TypeIDFromContentType returns the type id a MIME type names, and whether it
// named one at all. An unrecognized type is reported rather than guessed at:
// Multipass keeps unknown types and treats them as generic, and C1 must make
// the same distinction.
func TypeIDFromContentType(contentType string) (string, bool) {
	id, ok := strings.CutPrefix(contentType, contentTypePrefix)
	if !ok {
		return "", false
	}
	id, ok = strings.CutSuffix(id, contentTypeSuffix)
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// Tags classifies a field carrying a credential of the given type, for display
// and debugging in C1.
func Tags(id string) []string {
	return []string{"credential", "multipass", id}
}
