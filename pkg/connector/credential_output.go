package connector

import (
	"encoding/json"
	"fmt"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
)

// A Datadog organization API key is this connector's Multipass-typed
// credential output: Multipass binds the credential's type before issuance
// from what the descriptor declares, and reads the plaintext as that type's
// JSON afterwards. The type id, the MIME type that carries it, and the tags
// that mirror it are therefore declared exactly once here, so the descriptor
// and the payload the issuance returns cannot drift apart.
const (
	// multipassAPIKeyV2TypeID is the Multipass credential type for an API key.
	multipassAPIKeyV2TypeID = "api_key_v2"

	// multipassAPIKeyV2ContentType is the MIME type naming that credential
	// type: Multipass takes the type from the vendor suffix, and "+json" says
	// the payload is the JSON below rather than a bare key.
	multipassAPIKeyV2ContentType = "application/vnd.multipass." + multipassAPIKeyV2TypeID + "+json"

	// multipassTagCredential and multipassTagMultipass mark the field as a
	// Multipass credential; the type id is the third tag. The tags exist for
	// C1 display and debugging -- the MIME type above is what decides the type.
	multipassTagCredential = "credential"
	multipassTagMultipass  = "multipass"

	// datadogAPIKeyFieldName is the name this connector gives an organization
	// API key's plaintext, in both the descriptor's output field and the
	// PlaintextData its issuance returns.
	datadogAPIKeyFieldName = "api_key"

	// datadogProviderName is the api_key_v2 "provider" value for a Datadog key.
	datadogProviderName = "datadog"
)

// multipassAPIKeyV2Tags lists the tags mirroring the MIME type's type id. It
// returns a fresh slice per call: the descriptor builder keeps the slice it is
// handed, so a shared one would let a later mutation reach every descriptor.
func multipassAPIKeyV2Tags() []string {
	return []string{multipassTagCredential, multipassTagMultipass, multipassAPIKeyV2TypeID}
}

// multipassAPIKeyV2 is the Multipass api_key_v2 payload. Only key_value is
// required; every optional field is omitempty because Multipass rejects both
// unknown keys and nulls, so an unknown optional field has to be absent from
// the JSON rather than empty. encoding/json renders each of these as a string,
// so omitting an empty one is the only way it can be left out.
type multipassAPIKeyV2 struct {
	// KeyValue is the credential itself: the plaintext Datadog API key.
	KeyValue string `json:"key_value"`
	// KeyID is Datadog's identifier for the key, when the create response
	// reported one. It is not the credential, but it is what an operator or
	// Multipass can use to find or revoke the key without the secret.
	KeyID    string `json:"key_id,omitempty"`
	Provider string `json:"provider,omitempty"`
	// BaseURL is the Datadog API endpoint the key authenticates against, which
	// is what tells a holder of the key where to send it.
	BaseURL string `json:"base_url,omitempty"`
}

// encodeMultipassAPIKeyV2 renders the api_key_v2 payload Multipass reads for
// this credential. It refuses a payload with no key_value rather than emitting
// one: key_value is the only required field, so a payload without it is a bug
// worth failing loudly on, not a credential worth handing out.
func encodeMultipassAPIKeyV2(payload multipassAPIKeyV2) ([]byte, error) {
	if payload.KeyValue == "" {
		return nil, fmt.Errorf("baton-datadog: %s payload requires key_value", multipassAPIKeyV2TypeID)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: encode %s payload: %w", multipassAPIKeyV2ContentType, err)
	}
	return encoded, nil
}

// organizationAPIKeyOutput declares what Issue returns for the organization API
// key descriptor: a secret field carrying api_key_v2 JSON. C1 resolves the
// credential's type from this before issuance, so it must agree with the
// PlaintextData.Schema the issuance sets -- both come from the constants above.
func multipassAPIKeyV2Output() *config.Field {
	return config.Field_builder{
		Name:        datadogAPIKeyFieldName,
		DisplayName: "Datadog API key",
		ContentType: multipassAPIKeyV2ContentType,
		Tags:        multipassAPIKeyV2Tags(),
		IsSecret:    true,
	}.Build()
}
