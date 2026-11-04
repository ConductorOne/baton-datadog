package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-datadog/pkg/multipass"
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
		"key_value": "org-key-secret",
		"key_id":    "org-key-id",
		"provider":  datadogProviderName,
		"base_url":  "https://api.example.com",
	}, payload, "exactly these keys, no extras")
	for key, value := range payload {
		require.NotNil(t, value, "%s must be omitted rather than null", key)
	}

	require.Equal(t, datadogAPIKeyFieldName, plaintext.GetName())
	require.Equal(t, multipass.ContentType(multipass.TypeAPIKeyV2), plaintext.GetSchema(),
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

// TestOrgAPIKeyDescriptorDeclaresMultipassOutput: the descriptor is where C1
// learns the type before issuance, so it must name the same type the plaintext
// is encoded as. The service-account application key is not Multipass typed and
// must keep declaring nothing.
func TestOrgAPIKeyDescriptorDeclaresMultipassOutput(t *testing.T) {
	details, _, err := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true, true, testAPIBaseURL).IssueCapabilityDetails(context.Background())
	require.NoError(t, err)

	byType := map[string]*v2.CredentialIssueOptionDescriptor{}
	for _, o := range details.GetOptions() {
		byType[o.GetSecretResourceTypeId()] = o
	}

	output := byType[apiTokenResourceType.Id].GetOutput()
	require.NotNil(t, output, "the organization API key descriptor must declare its output")
	require.Equal(t, datadogAPIKeyFieldName, output.GetName())
	require.Equal(t, datadogAPIKeyDisplayName, output.GetDisplayName())
	require.Equal(t, multipass.ContentType(multipass.TypeAPIKeyV2), output.GetContentType())
	require.Equal(t, multipass.Tags(multipass.TypeAPIKeyV2), output.GetTags())
	require.True(t, output.GetIsSecret(), "the declared output is a credential")

	require.Nil(t, byType[serviceAccountApplicationKeyResourceType.Id].GetOutput(),
		"the service-account application key is not a Multipass-typed payload")
}
