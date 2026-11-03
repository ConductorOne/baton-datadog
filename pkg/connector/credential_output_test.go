package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/secret"
	"github.com/stretchr/testify/require"
)

// newMultipassOrgKeyServer serves just enough of the organization API key endpoint
// to mint one key, and reports Datadog's id and secret for it.
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

// issueMultipassOrgKey drives the organization API key issuance arm against the fake
// provider and returns what it produced.
func issueMultipassOrgKey(t *testing.T, server *httptest.Server) *connectorbuilder.CredentialIssueOutput {
	t.Helper()
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, true)
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

// TestOrgAPIKeyPlaintextIsMultipassAPIKeyV2 is the payload contract Multipass
// enforces after issuance: an object whose only required field is key_value,
// carrying exactly the api_key_v2 keys this connector fills in. Multipass
// rejects unknown keys and nulls, so the payload must add nothing and must
// omit -- not null -- any optional field it has no value for.
func TestOrgAPIKeyPlaintextIsMultipassAPIKeyV2(t *testing.T) {
	out := issueMultipassOrgKey(t, newMultipassOrgKeyServer(t))

	// Decode into a map so the assertion is about the keys on the wire, not
	// about this connector's own struct tags agreeing with themselves.
	var payload map[string]any
	require.NoError(t, json.Unmarshal(out.PlaintextData[0].GetBytes(), &payload),
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
	require.Equal(t, "org-key-secret", payload["key_value"],
		"key_value is the credential itself and must be the issued key")
}

// TestOrgAPIKeyPlaintextOmitsAbsentKeyID: Datadog's create response may report
// no usable id. key_id is optional in api_key_v2 and nulls are rejected, so it
// has to be absent from the JSON rather than empty or null.
func TestOrgAPIKeyPlaintextOmitsAbsentKeyID(t *testing.T) {
	plaintext, err := organizationAPIKeyPlaintext(organizationAPIKeyPayload("org-key-secret", "", ""))
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext.GetBytes(), &payload))
	require.Equal(t, map[string]any{
		"key_value": "org-key-secret",
		"provider":  datadogProviderName,
	}, payload)
	require.NotContains(t, string(plaintext.GetBytes()), "null")
}

// TestOrgAPIKeyPlaintextSchemaMatchesDescriptor: C1 binds the credential's type
// from the descriptor before issuance and reads the plaintext as that type
// afterwards. Both sides come from the SDK's secret.TypeAPIKeyV2, so a reveal
// cannot decode the payload as a type it is not.
func TestOrgAPIKeyPlaintextSchemaMatchesDescriptor(t *testing.T) {
	wantType := secret.TypeAPIKeyV2
	wantSchema := secret.ContentType(wantType)

	out := issueMultipassOrgKey(t, newMultipassOrgKeyServer(t))

	require.Equal(t, wantSchema, out.PlaintextData[0].GetSchema())
	require.Equal(t, "application/vnd.multipass.api_key_v2+json", wantSchema,
		"Multipass takes the credential type from the vendor suffix of the MIME type")
	require.Equal(t, datadogAPIKeyFieldName, out.PlaintextData[0].GetName())

	// The schema must survive a round trip back to the type id, or C1 and
	// Multipass would disagree about what the payload is.
	typeID, ok := secret.TypeIDFromContentType(out.PlaintextData[0].GetSchema())
	require.True(t, ok)
	require.Equal(t, wantType, typeID)
}

// TestIssuanceDeclaresMultipassOutputForOrgAPIKey: the descriptor is where C1
// learns the type, so it must declare the same MIME type and tags the payload
// carries -- and the service-account application key, which is not Multipass
// typed, must keep declaring nothing.
func TestIssuanceDeclaresMultipassOutputForOrgAPIKey(t *testing.T) {
	details, _, err := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true, true).IssueCapabilityDetails(context.Background())
	require.NoError(t, err)

	byType := map[string]*v2.CredentialIssueOptionDescriptor{}
	for _, o := range details.GetOptions() {
		byType[o.GetSecretResourceTypeId()] = o
	}

	orgKey, ok := byType[apiTokenResourceType.Id]
	require.True(t, ok)
	output := orgKey.GetOutput()
	require.NotNil(t, output, "the organization API key descriptor must declare its output")
	require.Equal(t, datadogAPIKeyFieldName, output.GetName())
	require.Equal(t, datadogAPIKeyDisplayName, output.GetDisplayName())
	require.Equal(t, secret.ContentType(secret.TypeAPIKeyV2), output.GetContentType())
	require.Equal(t, []string{"credential", "multipass", secret.TypeAPIKeyV2}, output.GetTags())
	require.True(t, output.GetIsSecret(), "the declared output is a credential")

	appKey, ok := byType[serviceAccountApplicationKeyResourceType.Id]
	require.True(t, ok)
	require.Nil(t, appKey.GetOutput(),
		"the service-account application key is not a Multipass-typed payload")
}
