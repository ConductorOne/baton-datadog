package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/stretchr/testify/require"
)

// Both existing API_KEY selectors must produce native bytes through the real
// Baton SDK encryption path while retaining their existing provider handles.
func TestExistingDatadogAPIKeyKindsIssueNativePayloads(t *testing.T) {
	const appPath = "/api/v2/service_accounts/sa-1/application_keys"
	const appValue = "app<>&fixture"
	const orgValue = "org<>&fixture"
	var mu sync.Mutex
	appCreates, orgCreates := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appPath:
			mu.Lock()
			appCreates++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":"app-native-id","type":"application_keys",` +
				`"attributes":{"key":"` + appValue + `","name":"c1-native-app","scopes":["granted_scope"]}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			mu.Lock()
			orgCreates++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":"org-native-id","type":"api_keys",` +
				`"attributes":{"key":"` + orgValue + `","name":"c1-native-org"}}}`))
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

	cases := []struct {
		name, identity, kind, requestID, resourceID, plaintextName, expected string
		scopes                                                               []string
	}{
		{name: "service account application key", identity: "sa-1", kind: serviceAccountApplicationKeyResourceType.Id,
			requestID: "native-app", resourceID: "app-native-id", plaintextName: "application_key", scopes: []string{"requested_scope"},
			expected: `{"key_value":"` + appValue + `","provider":"datadog","scopes":["granted_scope"],"key_id":"app-native-id","header_name":"DD-APPLICATION-KEY"}`},
		{name: "organization API key", identity: "user-1", kind: apiTokenResourceType.Id,
			requestID: "native-org", resourceID: "org-native-id", plaintextName: "api_key",
			expected: `{"key_value":"` + orgValue + `","provider":"datadog","key_id":"org-native-id","header_name":"DD-API-KEY"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := sdk.IssueCredential(ctx, v2.IssueCredentialRequest_builder{
				IdentityId: v2.ResourceId_builder{ResourceType: userResourceType.Id, Resource: tc.identity}.Build(),
				CredentialOptions: v2.CredentialIssueOptions_builder{
					SecretResourceTypeId: tc.kind,
					ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{Scopes: tc.scopes}.Build(),
				}.Build(),
				EncryptionConfigs: []*v2.EncryptionConfig{config}, RequestId: tc.requestID,
			}.Build())
			require.NoError(t, err)
			require.Equal(t, tc.kind, response.GetSecret().GetId().GetResourceType())
			require.Equal(t, tc.resourceID, response.GetSecret().GetId().GetResource())
			require.Len(t, response.GetEncryptedData(), 1)
			plaintext, err := (&jwk.JWKEncryptionProvider{}).Decrypt(ctx, response.GetEncryptedData()[0], privateKey)
			require.NoError(t, err)
			require.Equal(t, tc.plaintextName, plaintext.GetName())
			require.Equal(t, []byte(tc.expected), plaintext.GetBytes())
		})
	}
	mu.Lock()
	require.Equal(t, 1, appCreates)
	require.Equal(t, 1, orgCreates)
	mu.Unlock()
}
