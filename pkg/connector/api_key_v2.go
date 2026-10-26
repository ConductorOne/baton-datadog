package connector

import (
	"errors"

	"github.com/conductorone/baton-sdk/pkg/secretcontracts"
)

// datadogKeyKind identifies the Datadog endpoint that minted a key.
type datadogKeyKind string

const (
	serviceAccountApplicationKeyKind datadogKeyKind = "service-account-application-key"
	organizationAPIKeyKind           datadogKeyKind = "api-key"
)

// encodeDatadogAPIKeyV2 prepares the Multipass api_key_v2 plaintext through the
// SDK contract helper, which validates it and returns the content type with the
// bytes.
// keyValue must be the one-time key secret, while keyID is its provider handle.
// Service-account application-key scopes must come from Datadog's create
// response, rather than the requested scopes. Org API keys have no scopes.
// The encrypted issuance actions emit this document. Legacy IssueCredential
// selectors continue to deliver raw values.
func encodeDatadogAPIKeyV2(kind datadogKeyKind, keyValue, keyID string, scopes *[]string) (secretcontracts.Payload, error) {
	if keyValue == "" || keyID == "" {
		return secretcontracts.Payload{}, errors.New("datadog native API key requires a key value and provider key ID")
	}
	document := secretcontracts.APIKeyV2{KeyValue: keyValue, Provider: "datadog", KeyID: keyID}
	switch kind {
	case serviceAccountApplicationKeyKind:
		document.HeaderName = "DD-APPLICATION-KEY"
		if scopes != nil {
			document.Scopes = *scopes
		}
	case organizationAPIKeyKind:
		if scopes != nil {
			return secretcontracts.Payload{}, errors.New("datadog organization API keys cannot have scopes")
		}
		document.HeaderName = "DD-API-KEY"
	default:
		return secretcontracts.Payload{}, errors.New("unsupported datadog native API key kind")
	}
	return document.Encode()
}

// encodeDatadogServiceAccessTokenV2 describes a standalone Datadog SAT.
// Authorization is a header name; api_key_v2 has no field for its Bearer
// scheme. Datadog returns an instant expiry, while the profile only has a
// date, so the expiry remains on the secret trait rather than this payload.
func encodeDatadogServiceAccessTokenV2(keyValue, keyID string, scopes []string) (secretcontracts.Payload, error) {
	if keyValue == "" || keyID == "" {
		return secretcontracts.Payload{}, errors.New("datadog service access token requires a key value and provider token ID")
	}
	return secretcontracts.APIKeyV2{
		KeyValue: keyValue, Provider: "datadog", KeyID: keyID, HeaderName: "Authorization", Scopes: scopes,
	}.Encode()
}
