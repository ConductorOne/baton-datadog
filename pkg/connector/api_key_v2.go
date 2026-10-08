package connector

import (
	"encoding/json"
	"errors"
)

// datadogKeyKind identifies the Datadog endpoint that minted a key. A native
// payload can only be selected when the caller has an independent, durable way
// to associate the provider key with that payload. Datadog permits renaming
// both kinds of keys, so their names cannot provide that association at sync.
type datadogKeyKind string

const (
	serviceAccountApplicationKeyKind datadogKeyKind = "service-account-application-key"
	organizationAPIKeyKind           datadogKeyKind = "api-key"
)

type apiKeyV2Payload struct {
	KeyValue   string    `json:"key_value"`
	Provider   string    `json:"provider"`
	Scopes     *[]string `json:"scopes,omitempty"`
	KeyID      string    `json:"key_id"`
	HeaderName string    `json:"header_name"`
}

// encodeDatadogAPIKeyV2 prepares the Multipass api_key_v2 JsonV1 plaintext.
// keyValue must be the one-time key secret, while keyID is its provider handle.
// Service-account application-key scopes must come from Datadog's create
// response, rather than the requested scopes. Org API keys have no scopes.
// This encoder does not change the current raw credential Issue contract.
func encodeDatadogAPIKeyV2(kind datadogKeyKind, keyValue, keyID string, scopes *[]string) ([]byte, error) {
	if keyValue == "" || keyID == "" {
		return nil, errors.New("Datadog native API key requires a key value and provider key ID")
	}
	payload := apiKeyV2Payload{
		KeyValue: keyValue,
		Provider: "datadog",
		KeyID:    keyID,
	}
	switch kind {
	case serviceAccountApplicationKeyKind:
		payload.HeaderName = "DD-APPLICATION-KEY"
		payload.Scopes = scopes
	case organizationAPIKeyKind:
		if scopes != nil {
			return nil, errors.New("Datadog organization API keys cannot have scopes")
		}
		payload.HeaderName = "DD-API-KEY"
	default:
		return nil, errors.New("unsupported Datadog native API key kind")
	}
	return json.Marshal(payload)
}

// encodeDatadogServiceAccessTokenV2 describes a standalone Datadog SAT.
// Authorization is a header name; api_key_v2 has no field for its Bearer
// scheme. Datadog returns an instant expiry, while the profile only has a
// date, so the expiry remains on the secret trait rather than this payload.
func encodeDatadogServiceAccessTokenV2(keyValue, keyID string, scopes []string) ([]byte, error) {
	if keyValue == "" || keyID == "" {
		return nil, errors.New("Datadog service access token requires a key value and provider token ID")
	}
	payload := apiKeyV2Payload{
		KeyValue:   keyValue,
		Provider:   "datadog",
		KeyID:      keyID,
		HeaderName: "Authorization",
	}
	if scopes != nil {
		payload.Scopes = &scopes
	}
	return json.Marshal(payload)
}
