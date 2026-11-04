package connector

import (
	"github.com/conductorone/baton-datadog/pkg/multipass"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

const (
	// datadogAPIKeyFieldName is the name of the plaintext an issued
	// organization API key comes back under, in both the descriptor and the
	// PlaintextData.
	datadogAPIKeyFieldName = "api_key"

	// datadogAPIKeyDisplayName is how C1 labels that field.
	datadogAPIKeyDisplayName = "Datadog API key" //nolint:gosec // Display label, not a credential.

	// datadogApplicationKeyFieldName is the same, for a service account
	// application key.
	datadogApplicationKeyFieldName = "application_key"

	// datadogApplicationKeyDisplayName is how C1 labels that field.
	datadogApplicationKeyDisplayName = "Datadog application key"

	// datadogProviderName is the api_key_v2 "provider" value for a Datadog key.
	datadogProviderName = "datadog"

	// The header each kind of Datadog key is sent in. These are header names,
	// not credentials.
	datadogAPIKeyHeaderName         = "DD-API-KEY" //nolint:gosec // Header name, not a credential.
	datadogApplicationKeyHeaderName = "DD-APPLICATION-KEY"
)

// organizationAPIKeyOutput declares the type an issued organization API key
// comes back as. C1 binds the type before issuance, so this and the plaintext
// the issuance returns must name the same type; both derive from
// multipass.ContentType.
func organizationAPIKeyOutput() *configv1.Field {
	output := multipass.OutputField(datadogAPIKeyFieldName)
	output.SetDisplayName(datadogAPIKeyDisplayName)
	return output
}

// serviceAccountApplicationKeyOutput declares the type an issued service
// account application key comes back as, the same way.
func serviceAccountApplicationKeyOutput() *configv1.Field {
	output := multipass.OutputField(datadogApplicationKeyFieldName)
	output.SetDisplayName(datadogApplicationKeyDisplayName)
	return output
}

// organizationAPIKeyDescriptor is the descriptor the connector advertises for
// the organization API key, and the one its credential-issue action is built
// from. Declaring it once means the advertised shape, the action's schema and
// the validated output cannot drift apart.
func organizationAPIKeyDescriptor() *v2.CredentialIssueOptionDescriptor {
	return v2.CredentialIssueOptionDescriptor_builder{
		Option:       v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
		ResourceMode: v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
		// deletableAPITokenResourceType, not apiTokenResourceType: they share an
		// id, and this is the variant registered whenever this descriptor is
		// advertised.
		SecretResourceTypeId: deletableAPITokenResourceType.Id,
		// Datadog organization API keys carry no scopes. Advertising none and
		// disallowing custom ones makes the SDK reject a scoped request for this
		// kind before it reaches Issue.
		Output: organizationAPIKeyOutput(),
	}.Build()
}

// serviceAccountApplicationKeyDescriptor is the same for the application key.
// Preferred is left unset here; the capability builder decides it, because it is
// a property of the advertised set rather than of either kind.
func serviceAccountApplicationKeyDescriptor() *v2.CredentialIssueOptionDescriptor {
	return v2.CredentialIssueOptionDescriptor_builder{
		Option:               v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
		ResourceMode:         v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
		SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
		CustomScopesAllowed:  true,
		Output:               serviceAccountApplicationKeyOutput(),
	}.Build()
}
