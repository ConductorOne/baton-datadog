package connector

import (
	"fmt"

	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/secret"
)

// A Datadog organization API key is this connector's Multipass-typed
// credential output: Multipass binds the credential's type before issuance from
// what the descriptor declares, and reads the plaintext as that type's JSON
// afterwards. Both halves come from the SDK's secret package, so the declared
// type and the emitted payload are the same value rather than two things that
// have to be kept in step.
const (
	// datadogAPIKeyFieldName is the name this connector gives an organization
	// API key's plaintext, in both the descriptor's output field and the
	// PlaintextData its issuance returns.
	datadogAPIKeyFieldName = "api_key"

	// datadogAPIKeyDisplayName is how C1 labels that field.
	datadogAPIKeyDisplayName = "Datadog API key"

	// datadogProviderName is the api_key_v2 "provider" value for a Datadog key.
	datadogProviderName = "datadog"
)

// organizationAPIKeyPayload is the api_key_v2 value for a freshly minted
// organization API key. key_value is the credential itself; key_id is Datadog's
// own id for the key, which lets an operator find or revoke it without the
// secret; base_url is the API endpoint the key works against, which is what
// tells a holder where to send it.
//
// The remaining api_key_v2 fields are left empty on purpose and omitted from
// the JSON: a Datadog organization API key has no scopes, no header name and no
// expiry it is issued with. Multipass rejects unknown keys and nulls, so an
// unset optional field must be absent rather than empty, which is what the
// shared type's omitempty tags do.
func organizationAPIKeyPayload(keyValue, keyID, baseURL string) secret.APIKeyV2 {
	return secret.APIKeyV2{
		KeyValue: keyValue,
		KeyID:    keyID,
		Provider: datadogProviderName,
		BaseURL:  baseURL,
	}
}

// organizationAPIKeyPlaintext renders that payload and sets the schema its type
// names. Doing both through one helper is what keeps PlaintextData.Schema in
// agreement with the descriptor below.
func organizationAPIKeyPlaintext(payload secret.APIKeyV2) (*v2.PlaintextData, error) {
	plaintext, err := secret.Plaintext(datadogAPIKeyFieldName, payload)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: encode %s payload: %w", secret.ContentType(secret.TypeAPIKeyV2), err)
	}
	return plaintext, nil
}

// organizationAPIKeyOutput declares what Issue returns for the organization API
// key descriptor: a secret field carrying api_key_v2 JSON. C1 resolves the
// credential's type from this before issuance, so it must name the same type
// the plaintext above is encoded as -- both come from secret.TypeAPIKeyV2.
func organizationAPIKeyOutput() *configv1.Field {
	output := secret.OutputField(datadogAPIKeyFieldName, secret.TypeAPIKeyV2)
	output.SetDisplayName(datadogAPIKeyDisplayName)
	return output
}
