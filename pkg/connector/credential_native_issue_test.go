package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"filippo.io/hpke"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwe"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

// The three new actions return native bytes through the SDK encrypted action
// path while retaining the existing provider handles.
func TestDatadogAPIKeyActionsIssueNativePayloads(t *testing.T) {
	const appPath = "/api/v2/service_accounts/sa-1/application_keys"
	const appValue = "app<>&fixture"
	const orgValue = "org<>&fixture"
	var mu sync.Mutex
	appCreates, orgCreates, satCreates := 0, 0, 0
	appDeletes, orgDeletes, satDeletes := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appPath:
			mu.Lock()
			appCreates++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":"app-native-id","type":"application_keys",` +
				`"attributes":{"key":"` + appValue + `","name":"c1-native-app","scopes":["granted_scope"]}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens":
			mu.Lock()
			satCreates++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":"sat-native-id","type":"service_access_tokens",` +
				`"attributes":{"key":"sat-native-value","name":"c1-native-sat","scopes":["granted_scope"]},` +
				`"relationships":{"owned_by":{"data":{"id":"sa-1","type":"service_account"}}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			mu.Lock()
			orgCreates++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":"org-native-id","type":"api_keys",` +
				`"attributes":{"key":"` + orgValue + `","name":"c1-native-org"}}}`))
		case r.Method == http.MethodDelete && r.URL.Path == appPath+"/app-native-id":
			mu.Lock()
			appDeletes++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/api_keys/org-native-id":
			mu.Lock()
			orgDeletes++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens/sat-native-id":
			mu.Lock()
			satDeletes++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	sdk, err := connectorbuilder.NewConnector(ctx, &Datadog{
		wrapper: newLifecycleTestWrapper(server.URL), SyncSecrets: true,
		AllowOrgAPIKeyDeletion: true, SyncServiceAccountApplicationKeys: true,
	})
	require.NoError(t, err)
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	require.NoError(t, err)
	publicBytes := privateKey.PublicKey().Bytes()
	const keyID = "credential-ticket-key"
	const aad = "ticket/approved-identity/credential"
	publicJWK, err := json.Marshal(map[string]string{
		"kty": "AKP", "alg": jwe.Algorithm, "pub": base64.RawURLEncoding.EncodeToString(publicBytes),
		"kid": keyID, "use": "enc",
	})
	require.NoError(t, err)
	config := v2.EncryptionConfig_builder{
		Provider: jwe.EncryptionProvider, KeyId: keyID,
		JwkPublicKeyConfig: v2.EncryptionConfig_JWKPublicKeyConfig_builder{
			PubKey: publicJWK, AdditionalAuthenticatedData: []byte(aad),
		}.Build(),
	}.Build()

	cases := []struct {
		name, action, identity, kind, requestID, resourceID, plaintextName, expected string
		scopes                                                                       []string
	}{
		{name: "service account application key", action: ActionIssueServiceAccountApplicationKey, identity: "sa-1", kind: serviceAccountApplicationKeyResourceType.Id,
			requestID: "native-app", resourceID: "app-native-id", plaintextName: "application_key", scopes: []string{"requested_scope"},
			expected: `{"key_value":"` + appValue + `","provider":"datadog","scopes":["granted_scope"],"key_id":"app-native-id","header_name":"DD-APPLICATION-KEY"}`},
		{name: "service account access token", action: ActionIssueServiceAccountAccessToken, identity: "sa-1", kind: serviceAccountAccessTokenResourceType.Id,
			requestID: "native-sat", resourceID: serviceAccessTokenHandle("sa-1", "sat-native-id"), plaintextName: "service_access_token", scopes: []string{"requested_scope"},
			expected: `{"key_value":"sat-native-value","provider":"datadog","scopes":["granted_scope"],"key_id":"sat-native-id","header_name":"Authorization"}`},
		{name: "organization API key", action: ActionIssueOrganizationAPIKey, identity: "user-1", kind: apiTokenResourceType.Id,
			requestID: "native-org", resourceID: "org-native-id", plaintextName: "api_key",
			expected: `{"key_value":"` + orgValue + `","provider":"datadog","key_id":"org-native-id","header_name":"DD-API-KEY"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := structpb.NewStruct(map[string]any{
				"user_id":    map[string]any{"resource_type_id": userResourceType.Id, "resource_id": tc.identity},
				"request_id": tc.requestID,
			})
			require.NoError(t, err)
			if tc.scopes != nil {
				items := make([]any, len(tc.scopes))
				for i, scope := range tc.scopes {
					items[i] = scope
				}
				args.Fields["scopes"], err = structpb.NewValue(items)
				require.NoError(t, err)
			}
			response, err := sdk.InvokeAction(ctx, v2.InvokeActionRequest_builder{
				Name: tc.action, ResourceTypeId: userResourceType.Id, Args: args,
				EncryptionConfigs: []*v2.EncryptionConfig{config}, InlineWait: durationpb.New(5 * time.Second),
			}.Build())
			require.NoError(t, err)
			if response.GetStatus() != v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE {
				statusResponse, statusErr := sdk.GetActionStatus(ctx, v2.GetActionStatusRequest_builder{Id: response.GetId()}.Build())
				require.NoError(t, statusErr)
				require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE, statusResponse.GetStatus())
				require.Len(t, statusResponse.GetEncryptedData(), 1)
				response.SetEncryptedData(statusResponse.GetEncryptedData())
				response.SetResponse(statusResponse.GetResponse())
			}
			publicResource, ok := actions.GetResourceFieldArg(response.GetResponse(), "issued_resource")
			require.True(t, ok)
			require.Equal(t, tc.kind, publicResource.GetId().GetResourceType())
			require.Equal(t, tc.resourceID, publicResource.GetId().GetResource())
			require.NotContains(t, response.GetResponse().String(), tc.expected)
			require.Len(t, response.GetEncryptedData(), 1)
			encrypted := response.GetEncryptedData()[0]
			require.Equal(t, jwe.EncryptionProvider, encrypted.GetProvider())
			require.Equal(t, []string{keyID}, encrypted.GetKeyIds())
			require.Equal(t, tc.plaintextName, encrypted.GetName())
			require.Equal(t, "api_key_v2", encrypted.GetSchema())
			var message jwe.FlattenedJWE
			require.NoError(t, json.Unmarshal(encrypted.GetEncryptedBytes(), &message))
			require.Equal(t, base64.RawURLEncoding.EncodeToString([]byte(aad)), message.AAD)
			enc, err := base64.RawURLEncoding.DecodeString(message.EncryptedKey)
			require.NoError(t, err)
			ciphertext, err := base64.RawURLEncoding.DecodeString(message.Ciphertext)
			require.NoError(t, err)
			receiver, err := hpke.NewRecipient(enc, privateKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
			require.NoError(t, err)
			plaintext, err := receiver.Open([]byte(message.Protected+"."+message.AAD), ciphertext)
			require.NoError(t, err)
			require.Equal(t, []byte(tc.expected), plaintext)
			_, err = sdk.DeleteResourceV2(ctx, v2.DeleteResourceV2Request_builder{
				ResourceId: publicResource.GetId(), ParentResourceId: publicResource.GetParentResourceId(),
			}.Build())
			require.NoError(t, err)
			// Both AAD and the protected key-id are authenticated. A different
			// ticket context or recipient key cannot recover the credential.
			wrongAADReceiver, err := hpke.NewRecipient(enc, privateKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
			require.NoError(t, err)
			_, err = wrongAADReceiver.Open([]byte(message.Protected+"."+base64.RawURLEncoding.EncodeToString([]byte("wrong-ticket"))), ciphertext)
			require.Error(t, err)
			wrongKeyIDReceiver, err := hpke.NewRecipient(enc, privateKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
			require.NoError(t, err)
			_, err = wrongKeyIDReceiver.Open([]byte("wrong-protected-key-id."+message.AAD), ciphertext)
			require.Error(t, err)
		})
	}
	mu.Lock()
	require.Equal(t, 1, appCreates)
	require.Equal(t, 1, orgCreates)
	require.Equal(t, 1, satCreates)
	require.Equal(t, 1, appDeletes)
	require.Equal(t, 1, orgDeletes)
	require.Equal(t, 1, satDeletes)
	mu.Unlock()
}

// Existing IssueCredential selectors retain their raw plaintext contract while
// the separate actions supply native api_key_v2 documents.
func TestDatadogLegacyIssueCredentialKeepsRawBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v2/service_accounts/sa-1/application_keys" || r.URL.Path == "/api/v2/api_keys"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/service_accounts/sa-1/application_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"legacy-app-id","type":"application_keys","attributes":{"key":"legacy-app-value","name":"c1-legacy-app"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"legacy-org-id","type":"api_keys","attributes":{"key":"legacy-org-value","name":"c1-legacy-org"}}}`))
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	sdk, err := connectorbuilder.NewConnector(ctx, &Datadog{
		wrapper: newLifecycleTestWrapper(server.URL), SyncSecrets: true,
		AllowOrgAPIKeyDeletion: true, SyncServiceAccountApplicationKeys: true,
	})
	require.NoError(t, err)
	config, privateKey, err := (&jwk.JWKEncryptionProvider{}).GenerateKey(ctx)
	require.NoError(t, err)
	for _, tc := range []struct {
		kind, requestID, identity, want string
	}{
		{serviceAccountApplicationKeyResourceType.Id, "legacy-app", "sa-1", "legacy-app-value"},
		{apiTokenResourceType.Id, "legacy-org", "user-1", "legacy-org-value"},
	} {
		response, err := sdk.IssueCredential(ctx, v2.IssueCredentialRequest_builder{
			IdentityId: v2.ResourceId_builder{ResourceType: userResourceType.Id, Resource: tc.identity}.Build(),
			CredentialOptions: v2.CredentialIssueOptions_builder{
				SecretResourceTypeId: tc.kind,
				ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
			}.Build(),
			EncryptionConfigs: []*v2.EncryptionConfig{config}, RequestId: tc.requestID,
		}.Build())
		require.NoError(t, err)
		require.Len(t, response.GetEncryptedData(), 1)
		plaintext, err := (&jwk.JWKEncryptionProvider{}).Decrypt(ctx, response.GetEncryptedData()[0], privateKey)
		require.NoError(t, err)
		require.Equal(t, []byte(tc.want), plaintext.GetBytes())
		require.Empty(t, plaintext.GetSchema())
	}
}
