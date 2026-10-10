package connector

import (
	"bytes"
	"encoding/json"
	"errors"
)

// datadogKeyKind identifies the Datadog endpoint that minted a key.
type datadogKeyKind string

const (
	serviceAccountApplicationKeyKind datadogKeyKind = "service-account-application-key"
	organizationAPIKeyKind           datadogKeyKind = "api-key"
)

type apiKeyV2Payload struct {
	KeyValue   string   `json:"key_value"`
	Provider   string   `json:"provider"`
	Scopes     []string `json:"scopes,omitempty"`
	KeyID      string   `json:"key_id"`
	HeaderName string   `json:"header_name"`
}

// encodeDatadogAPIKeyV2 prepares the Multipass api_key_v2 JsonV1 plaintext.
// keyValue must be the one-time key secret, while keyID is its provider handle.
// Service-account application-key scopes must come from Datadog's create
// response, rather than the requested scopes. Org API keys have no scopes.
// The current API_KEY selectors emit this document as their plaintext value.
func encodeDatadogAPIKeyV2(kind datadogKeyKind, keyValue, keyID string, scopes *[]string) ([]byte, error) {
	if keyValue == "" || keyID == "" {
		return nil, errors.New("datadog native API key requires a key value and provider key ID")
	}
	payload := apiKeyV2Payload{
		KeyValue: keyValue,
		Provider: "datadog",
		KeyID:    keyID,
	}
	switch kind {
	case serviceAccountApplicationKeyKind:
		payload.HeaderName = "DD-APPLICATION-KEY"
		if scopes != nil {
			payload.Scopes = *scopes
		}
	case organizationAPIKeyKind:
		if scopes != nil {
			return nil, errors.New("datadog organization API keys cannot have scopes")
		}
		payload.HeaderName = "DD-API-KEY"
	default:
		return nil, errors.New("unsupported datadog native API key kind")
	}
	return marshalAPIKeyV2(payload)
}

// encodeDatadogServiceAccessTokenV2 describes a standalone Datadog SAT.
// Authorization is a header name; api_key_v2 has no field for its Bearer
// scheme. Datadog returns an instant expiry, while the profile only has a
// date, so the expiry remains on the secret trait rather than this payload.
func encodeDatadogServiceAccessTokenV2(keyValue, keyID string, scopes []string) ([]byte, error) {
	if keyValue == "" || keyID == "" {
		return nil, errors.New("datadog service access token requires a key value and provider token ID")
	}
	payload := apiKeyV2Payload{
		KeyValue:   keyValue,
		Provider:   "datadog",
		KeyID:      keyID,
		HeaderName: "Authorization",
	}
	payload.Scopes = scopes
	return marshalAPIKeyV2(payload)
}

// Multipass JsonV1 writes declaration-order keys and omits empty optional
// fields. Encoding the complete struct in that order, without Go's default
// HTML escaping, makes the plaintext byte-identical after decode/re-encode.
func marshalAPIKeyV2(payload apiKeyV2Payload) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}
