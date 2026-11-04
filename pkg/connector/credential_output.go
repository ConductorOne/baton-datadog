package connector

import (
	"github.com/conductorone/baton-datadog/pkg/multipass"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
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
// multipass.TypeAPIKeyV2.
func organizationAPIKeyOutput() *configv1.Field {
	output := multipass.OutputField(datadogAPIKeyFieldName, multipass.TypeAPIKeyV2)
	output.SetDisplayName(datadogAPIKeyDisplayName)
	return output
}

// serviceAccountApplicationKeyOutput declares the type an issued service
// account application key comes back as. Same contract as the organization
// key: the declared type and the plaintext must derive from
// multipass.TypeAPIKeyV2.
func serviceAccountApplicationKeyOutput() *configv1.Field {
	output := multipass.OutputField(datadogApplicationKeyFieldName, multipass.TypeAPIKeyV2)
	output.SetDisplayName(datadogApplicationKeyDisplayName)
	return output
}
