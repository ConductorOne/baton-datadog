package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-multipass-sdk/pkg/multipass"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
)

// newMultipassOrgKeyServer serves just enough of the organization API key
// endpoint to mint one key, and reports Datadog's id and secret for it.
func newMultipassOrgKeyServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"org-key-id","type":"api_keys","attributes":{"name":"c1-req-multipass","key":"org-key-secret"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// issueMultipassOrgKey drives the organization API key issuance arm against the
// fake provider and returns what it produced.
func issueMultipassOrgKey(t *testing.T, server *httptest.Server) *connectorbuilder.CredentialIssueOutput {
	t.Helper()
	return issueMultipassOrgKeyAt(t, server, testAPIBaseURL)
}

// issueMultipassOrgKeyAt is issueMultipassOrgKey with the advertised API
// endpoint chosen by the caller, so the base-url override path can be covered.
func issueMultipassOrgKeyAt(t *testing.T, server *httptest.Server, apiBaseURL string) *connectorbuilder.CredentialIssueOutput {
	t.Helper()
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, true, apiBaseURL)
	out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  "req-multipass",
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: apiTokenResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
	})
	require.NoError(t, err)
	require.Len(t, out.PlaintextData, 1)
	return out
}

// appKeyPlaintextKeyValue returns the key_value of an issued application key's
// api_key_v2 payload. Plaintext for this kind is JSON, not the bare key, so a
// test that wants the key itself has to read it out of the document.
func appKeyPlaintextKeyValue(t *testing.T, out *connectorbuilder.CredentialIssueOutput) string {
	t.Helper()
	require.Len(t, out.PlaintextData, 1)
	var payload struct {
		KeyValue string `json:"key_value"`
	}
	require.NoError(t, json.Unmarshal(out.PlaintextData[0].GetBytes(), &payload),
		"the application key plaintext must be api_key_v2 JSON")
	return payload.KeyValue
}

// TestOrgAPIKeyIssueEmitsMultipassAPIKeyV2 is the payload contract Multipass
// enforces after issuance: an object whose only required field is key_value,
// carrying exactly the api_key_v2 keys this connector fills in. Decoded into a
// map so the assertion is about the keys on the wire, not about the SDK struct
// agreeing with itself.
func TestOrgAPIKeyIssueEmitsMultipassAPIKeyV2(t *testing.T) {
	out := issueMultipassOrgKey(t, newMultipassOrgKeyServer(t))
	plaintext := out.PlaintextData[0]

	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext.GetBytes(), &payload),
		"the plaintext must be JSON, not the bare key")
	require.Equal(t, map[string]any{
		"key_value":   "org-key-secret",
		"key_id":      "org-key-id",
		"provider":    datadogProviderName,
		"base_url":    "https://api.example.com",
		"header_name": datadogAPIKeyHeaderName,
	}, payload, "exactly these keys, no extras")
	for key, value := range payload {
		require.NotNil(t, value, "%s must be omitted rather than null", key)
	}

	require.Equal(t, datadogAPIKeyFieldName, plaintext.GetName())
	require.Equal(t, multipass.ContentType, plaintext.GetSchema(),
		"the schema must name the type the descriptor declares")
}

// TestOrgAPIKeyBaseURLFollowsOverride: the connector can be pointed at a
// different Datadog API with base-url, and an issued key has to advertise the
// endpoint it actually works against rather than the one its site implies.
func TestOrgAPIKeyBaseURLFollowsOverride(t *testing.T) {
	const override = "https://dd.example.test"
	out := issueMultipassOrgKeyAt(t, newMultipassOrgKeyServer(t), override)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(out.PlaintextData[0].GetBytes(), &payload))
	require.Equal(t, override, payload["base_url"])

	// And the site-derived endpoint must not leak through instead.
	require.NotEqual(t, "https://api.example.com", payload["base_url"],
		"the override must win over the site")
}

// TestDatadogAPIBaseURL: the override wins when set, and the site decides
// otherwise.
func TestDatadogAPIBaseURL(t *testing.T) {
	require.Equal(t, "https://api.datadoghq.eu", (&Datadog{site: "datadoghq.eu"}).apiBaseURL())
	require.Equal(t, "https://dd.example.test", (&Datadog{site: "datadoghq.eu", baseURL: "https://dd.example.test"}).apiBaseURL(),
		"the base-url override must win over the site")
}

// TestIssuerOutputFieldsDeclareMultipass: C1 learns the credential's type from
// the declared field before issuance, so it must name the same type the
// plaintext is encoded as. Both credential kinds declare one.
func TestIssuerOutputFieldsDeclareMultipass(t *testing.T) {
	for _, tt := range []struct {
		name        string
		output      *configv1.Field
		wantName    string
		wantDisplay string
	}{
		{"organization API key", organizationAPIKeyOutput(), datadogAPIKeyFieldName, datadogAPIKeyDisplayName},
		{"application key", serviceAccountApplicationKeyOutput(), datadogApplicationKeyFieldName, datadogApplicationKeyDisplayName},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantName, tt.output.GetName())
			require.Equal(t, tt.wantDisplay, tt.output.GetDisplayName())
			require.Equal(t, multipass.ContentType, tt.output.GetContentType())
			require.Equal(t, multipass.Tags(), tt.output.GetTags())
			require.True(t, tt.output.GetIsSecret(), "the declared output is a credential")
		})
	}
}

// newMultipassAppKeyServer serves the service-account application key endpoints
// needed to mint one key, with the response's attributes supplied by the caller
// so the scopes shapes can be covered. It records DELETEs so cleanup can be
// asserted.
func newMultipassAppKeyServer(t *testing.T, handle, secret, attrsJSON string) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := &[]recordedRequest{}
	appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":{"id":"` + handle + `","type":"application_keys","attributes":` + attrsJSON + `}}`))
		case r.Method == http.MethodDelete && r.URL.Path == appKeysPath+"/"+handle:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

// issueMultipassAppKey drives the application key issuance arm and returns the
// decoded payload.
func issueMultipassAppKey(t *testing.T, server *httptest.Server) map[string]any {
	t.Helper()
	issued := issueServiceAccountAppKey(t, context.Background(), newLifecycleTestWrapper(server.URL), testServiceAccountID, "req-app")
	require.Len(t, issued.PlaintextData, 1)
	plaintext := issued.PlaintextData[0]
	require.Equal(t, datadogApplicationKeyFieldName, plaintext.GetName())
	require.Equal(t, multipass.ContentType, plaintext.GetSchema(),
		"the schema must name the type the descriptor declares")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext.GetBytes(), &payload),
		"the plaintext must be JSON, not the bare key")
	for key, value := range payload {
		require.NotNil(t, value, "%s must be omitted rather than null", key)
	}
	return payload
}

// TestAppKeyIssueEmitsMultipassAPIKeyV2: the application key is typed the same
// way as the organization key, and carries the header it is sent in plus the
// scopes Datadog reported.
func TestAppKeyIssueEmitsMultipassAPIKeyV2(t *testing.T) {
	server, _ := newMultipassAppKeyServer(t, "app-key-id", "app-key-secret",
		`{"key":"app-key-secret","name":"c1-req-app","scopes":["logs_read"]}`)

	payload := issueMultipassAppKey(t, server)
	require.Equal(t, map[string]any{
		"key_value":   "app-key-secret",
		"key_id":      "app-key-id",
		"provider":    datadogProviderName,
		"base_url":    testAPIBaseURL,
		"header_name": datadogApplicationKeyHeaderName,
		"scopes":      []any{"logs_read"},
	}, payload)
}

// TestAppKeyIssueOmitsScopesWhenProviderDidNotReport: nil scopes means Datadog
// said nothing, which must leave the key absent rather than emit an empty list
// asserting the key is unscoped.
func TestAppKeyIssueOmitsScopesWhenProviderDidNotReport(t *testing.T) {
	server, _ := newMultipassAppKeyServer(t, "app-key-id", "app-key-secret",
		`{"key":"app-key-secret","name":"c1-req-app"}`)

	payload := issueMultipassAppKey(t, server)
	require.NotContains(t, payload, "scopes", "unreported scopes must be omitted, not empty")
}

// TestAppKeyIssueSendsScopesWhenReported: a provider-reported list is carried
// through, so a scoped key says what it can do.
func TestAppKeyIssueCarriesReportedScopes(t *testing.T) {
	server, _ := newMultipassAppKeyServer(t, "app-key-id", "app-key-secret",
		`{"key":"app-key-secret","name":"c1-req-app","scopes":["logs_read","metrics_read"]}`)

	payload := issueMultipassAppKey(t, server)
	require.Equal(t, []any{"logs_read", "metrics_read"}, payload["scopes"])
}
