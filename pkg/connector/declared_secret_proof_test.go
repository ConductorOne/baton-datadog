package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/hpke"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwe"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func datadogActionJWEConfig(t *testing.T) (*v2.EncryptionConfig, hpke.PrivateKey, []byte) {
	t.Helper()
	key, err := hpke.MLKEM768X25519().GenerateKey()
	require.NoError(t, err)
	const keyID = "datadog-declared-fixture"
	public, err := json.Marshal(map[string]string{"kty": "AKP", "alg": jwe.Algorithm, "kid": keyID, "use": "enc",
		"pub": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())})
	require.NoError(t, err)
	aad := []byte(`{"purpose":"c1/fk-credential-delivery","version":1,"content_type":"api_key_v2","ticket":"approved-fixture"}`)
	return v2.EncryptionConfig_builder{Provider: jwe.EncryptionProvider, KeyId: keyID,
		JwkPublicKeyConfig: v2.EncryptionConfig_JWKPublicKeyConfig_builder{PubKey: public, AdditionalAuthenticatedData: aad}.Build()}.Build(), key, aad
}

func openDatadogActionJWE(t *testing.T, encrypted *v2.EncryptedData, key hpke.PrivateKey, aad []byte) []byte {
	t.Helper()
	var message jwe.FlattenedJWE
	require.NoError(t, json.Unmarshal(encrypted.GetEncryptedBytes(), &message))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(aad), message.AAD)
	enc, err := base64.RawURLEncoding.DecodeString(message.EncryptedKey)
	require.NoError(t, err)
	ciphertext, err := base64.RawURLEncoding.DecodeString(message.Ciphertext)
	require.NoError(t, err)
	recipient, err := hpke.NewRecipient(enc, key, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
	require.NoError(t, err)
	plaintext, err := recipient.Open([]byte(message.Protected+"."+message.AAD), ciphertext)
	require.NoError(t, err)
	return plaintext
}

// TestDatadogDeclaredSecretProof can also consume a C1-prepared InvokeActionRequest
// and export the actual SDK response. The HTTP fixture is the only provider port.
func TestDatadogDeclaredSecretProof(t *testing.T) {
	const expected = `{"key_value":"datadog-fixture-only","provider":"datadog","scopes":["granted_scope"],"key_id":"app-proof-id","header_name":"DD-APPLICATION-KEY"}`
	var calls, creates atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/service_accounts/sa-1/application_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/service_accounts/sa-1/application_keys":
			creates.Add(1)
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			attributes := body["data"].(map[string]any)["attributes"].(map[string]any)
			require.Equal(t, []any{"requested_scope"}, attributes["scopes"])
			_, _ = w.Write([]byte(`{"data":{"id":"app-proof-id","type":"application_keys","attributes":{"key":"datadog-fixture-only","name":"c1-connector-proof","scopes":["granted_scope"]}}}`))
		default:
			t.Errorf("unexpected fixture request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	ctx := context.Background()
	sdk, err := connectorbuilder.NewConnector(ctx, &Datadog{wrapper: newLifecycleTestWrapper(provider.URL), SyncSecrets: true, SyncServiceAccountApplicationKeys: true})
	require.NoError(t, err)
	schemas, err := sdk.ListActionSchemas(ctx, v2.ListActionSchemasRequest_builder{ResourceTypeId: userResourceType.Id}.Build())
	require.NoError(t, err)
	var schema *v2.BatonActionSchema
	for _, candidate := range schemas.GetSchemas() {
		if candidate.GetName() == ActionIssueServiceAccountApplicationKey {
			schema = candidate
		}
	}
	require.NotNil(t, schema)
	for _, field := range schema.GetReturnTypes() {
		if field.GetIsSecret() {
			require.True(t, field.HasSecretContentType())
			require.Equal(t, "api_key_v2", field.GetSecretContentType())
		}
	}
	config, key, aad := datadogActionJWEConfig(t)
	request := v2.InvokeActionRequest_builder{Name: schema.GetName(), ResourceTypeId: schema.GetResourceTypeId(),
		Args:              issuanceArgs(t, "sa-1", "connector-proof", []any{"requested_scope"}),
		EncryptionConfigs: []*v2.EncryptionConfig{config}, InlineWait: durationpb.New(5 * time.Second)}.Build()
	for _, wrongAAD := range []string{"opaque-old-context", `{"purpose":"c1/fk-credential-delivery","version":1,"content_type":"generic"}`,
		`{"purpose":"wrong","version":1,"content_type":"api_key_v2"}`, `{"purpose":"c1/fk-credential-delivery","version":2,"content_type":"api_key_v2"}`} {
		wrong := proto.Clone(request).(*v2.InvokeActionRequest)
		wrong.GetEncryptionConfigs()[0].GetJwkPublicKeyConfig().SetAdditionalAuthenticatedData([]byte(wrongAAD))
		_, err := sdk.InvokeAction(ctx, wrong)
		require.Error(t, err)
		require.Zero(t, calls.Load(), "downgrade refusal precedes any provider request")
	}
	var input struct {
		Operation string          `json:"operation"`
		Request   json.RawMessage `json:"request"`
	}
	external := os.Getenv("CONNECTOR_SECRET_PROOF_INPUT")
	if external != "" {
		encoded, err := os.ReadFile(external)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(encoded, &input))
		if input.Operation == "invoke" {
			request = new(v2.InvokeActionRequest)
			require.NoError(t, protojson.Unmarshal(input.Request, request))
			request.SetArgs(issuanceArgs(t, "sa-1", "connector-proof", []any{"requested_scope"}))
			request.SetInlineWait(durationpb.New(5 * time.Second))
		}
	}
	output := map[string]any{"expected_payload_base64": base64.StdEncoding.EncodeToString([]byte(expected))}
	schemaJSON, err := protojson.Marshal(schema)
	require.NoError(t, err)
	output["schema"] = json.RawMessage(schemaJSON)
	if input.Operation != "schema" {
		response, err := sdk.InvokeAction(ctx, request)
		require.NoError(t, err)
		require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE, response.GetStatus())
		require.Len(t, response.GetEncryptedData(), 1)
		require.EqualValues(t, 1, creates.Load())
		require.NotContains(t, response.GetResponse().String(), "datadog-fixture-only")
		if external == "" {
			require.Equal(t, []byte(expected), openDatadogActionJWE(t, response.GetEncryptedData()[0], key, aad))
		}
		encoded, err := protojson.Marshal(response)
		require.NoError(t, err)
		output["response"] = json.RawMessage(encoded)
	}
	if path := os.Getenv("CONNECTOR_SECRET_PROOF_RESULT"); path != "" {
		encoded, err := json.MarshalIndent(output, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, encoded, 0o600))
	}
}
