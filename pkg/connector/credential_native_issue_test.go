package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"time"
)

// The three new actions return native bytes through the SDK encrypted action
// path while retaining the existing provider handles.
func TestDatadogAPIKeyActionsIssueNativePayloads(t *testing.T) {
	const appPath = "/api/v2/service_accounts/sa-1/application_keys"
	const appValue = "app<>&fixture"
	const orgValue = "org<>&fixture"
	var mu sync.Mutex
	appCreates, orgCreates, satCreates := 0, 0, 0
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
			plaintext, err := (&jwk.JWKEncryptionProvider{}).Decrypt(ctx, response.GetEncryptedData()[0], privateKey)
			require.NoError(t, err)
			require.Equal(t, tc.plaintextName, plaintext.GetName())
			require.Equal(t, "api_key_v2", plaintext.GetSchema())
			require.Equal(t, []byte(tc.expected), plaintext.GetBytes())
		})
	}
	mu.Lock()
	require.Equal(t, 1, appCreates)
	require.Equal(t, 1, orgCreates)
	require.Equal(t, 1, satCreates)
	mu.Unlock()
}
