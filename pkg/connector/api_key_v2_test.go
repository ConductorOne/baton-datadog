package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatadogAPIKeyV2Payload(t *testing.T) {
	tests := []struct {
		name       string
		kind       datadogKeyKind
		scopes     *[]string
		wantHeader string
	}{
		{"service account application key", serviceAccountApplicationKeyKind, &[]string{"dashboards_read", "logs_read"}, "DD-APPLICATION-KEY"},
		{"service account application key with reported empty scopes", serviceAccountApplicationKeyKind, &[]string{}, "DD-APPLICATION-KEY"},
		{"organization API key", organizationAPIKeyKind, nil, "DD-API-KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const secret = "secret-🔑-\"-\n"
			const id = "provider-handle"
			encoded, err := encodeDatadogAPIKeyV2(tt.kind, secret, id, tt.scopes)
			require.NoError(t, err)
			require.NotEqual(t, []byte(secret), encoded, "native plaintext is JSON, not the legacy raw key")

			// Check the exact Multipass api_key_v2 field set. JsonV1 rejects
			// unknown keys, so an extra connector field would break decoding.
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			wantKeys := []string{"key_value", "provider", "key_id", "header_name"}
			if tt.scopes != nil {
				wantKeys = append(wantKeys, "scopes")
			}
			require.ElementsMatch(t, wantKeys, mapKeys(fields))
			var gotSecret string
			require.NoError(t, json.Unmarshal(fields["key_value"], &gotSecret))
			require.Equal(t, secret, gotSecret)
			require.Equal(t, `"provider-handle"`, string(fields["key_id"]))
			require.Equal(t, `"datadog"`, string(fields["provider"]))
			require.Equal(t, `"`+tt.wantHeader+`"`, string(fields["header_name"]))
			if tt.scopes != nil {
				var gotScopes []string
				require.NoError(t, json.Unmarshal(fields["scopes"], &gotScopes))
				require.Equal(t, *tt.scopes, gotScopes)
			}
		})
	}
}

// The fixture traverses the official Datadog client response decoding before
// encoding. It catches a swapped provider ID/secret and verifies that only
// scopes echoed by Datadog enter the native payload.
func TestDatadogAPIKeyV2UsesProviderIssuedFields(t *testing.T) {
	const appKeyPath = "/api/v2/service_accounts/sa-1/application_keys"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == appKeyPath:
			_, _ = w.Write([]byte(`{"data":{"id":"app-provider-id","type":"application_keys","attributes":{"key":"app-secret","name":"fixture","scopes":["granted_scope"]}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"org-provider-id","type":"api_keys","attributes":{"key":"org-secret","name":"fixture"}}}`))
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	ctx := context.Background()

	appKey, err := wrapper.CreateServiceAccountApplicationKey(ctx, "sa-1", "fixture", []string{"requested_scope"})
	require.NoError(t, err)
	appPayload, err := encodeDatadogAPIKeyV2(serviceAccountApplicationKeyKind, appKey.Secret, appKey.ID, appKey.Scopes)
	require.NoError(t, err)
	require.JSONEq(t, `{"key_value":"app-secret","provider":"datadog","key_id":"app-provider-id","header_name":"DD-APPLICATION-KEY","scopes":["granted_scope"]}`, string(appPayload))

	orgKey, err := wrapper.CreateAPIKey(ctx, "fixture")
	require.NoError(t, err)
	orgPayload, err := encodeDatadogAPIKeyV2(organizationAPIKeyKind, orgKey.Secret, orgKey.ID, nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"key_value":"org-secret","provider":"datadog","key_id":"org-provider-id","header_name":"DD-API-KEY"}`, string(orgPayload))
}

func TestDatadogAPIKeyV2PayloadRejectsInvalidSource(t *testing.T) {
	for _, tc := range []struct {
		kind   datadogKeyKind
		secret string
		id     string
		scopes *[]string
	}{
		{organizationAPIKeyKind, "", "id", nil},
		{organizationAPIKeyKind, "secret", "", nil},
		{organizationAPIKeyKind, "secret", "id", &[]string{"invented_scope"}},
		{"unknown", "secret", "id", nil},
	} {
		encoded, err := encodeDatadogAPIKeyV2(tc.kind, tc.secret, tc.id, tc.scopes)
		require.Error(t, err)
		require.Nil(t, encoded)
	}
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
