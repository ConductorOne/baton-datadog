package secret

import (
	"strings"

	"github.com/conductorone/baton-sdk/pkg/field"
)

// Content type IDs, matching content_type in Multipass's
// crates/latchkey-client-sdk/src/secret_types/definitions.rs.
//
// hotp, note and generic use Multipass's UTF8_TEXT_V1 codec rather than a JSON
// document, so they have no struct here; the constants exist so a connector can
// still declare them.
const (
	TypePasswordV2          = "password_v2"
	TypeAPIKeyV2            = "api_key_v2" //nolint:gosec // Content type ID, not a credential.
	TypeSSHKey              = "ssh_key"
	TypeOAuthClientSecretV2 = "oauth_client_secret_v2" //nolint:gosec // Content type ID, not a credential.
	TypeCertificate         = "certificate"
	TypeHOTP                = "hotp"
	TypeNote                = "note"
	TypeGeneric             = "generic"
)

const contentTypePrefix = "application/vnd.multipass."
const contentTypeSuffix = "+json"

// ContentType returns the MIME type that carries a value of the given type.
// id must be a well-formed type ID: an ID containing / or empty yields a MIME
// type that TypeIDFromContentType rejects, so the two do not round-trip.
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

// tagMultipass marks a field whose value Multipass stores and types.
const tagMultipass = "multipass"

// kindTags names the credential kind each Multipass type is a carrying shape
// for. A type absent here has no kind in field's vocabulary, so its field
// carries only [credential, multipass, id].
var kindTags = map[string]field.FieldTag{
	TypeAPIKeyV2:            field.FieldTagAPIKey,
	TypePasswordV2:          field.FieldTagPassword,
	TypeSSHKey:              field.FieldTagSSHKey,
	TypeOAuthClientSecretV2: field.FieldTagOauthClientSecret,
	TypeCertificate:         field.FieldTagCertificate,
}

// Tags classifies a field carrying a credential of the given type, for display
// and debugging in C1.
func Tags(id string) []string {
	kind, ok := kindTags[id]
	if !ok {
		return []string{string(field.FieldTagCredential), tagMultipass, id}
	}
	return []string{string(field.FieldTagCredential), string(kind), tagMultipass, id}
}
