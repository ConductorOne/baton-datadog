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

	// datadogProviderName is the api_key_v2 "provider" value for a Datadog key.
	datadogProviderName = "datadog"
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
