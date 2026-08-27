package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestIssuanceAdvertisesBothCredentialKinds is the type-discriminator contract:
// two kinds of the same API_KEY shape, told apart only by
// secret_resource_type_id.
func TestIssuanceAdvertisesBothCredentialKinds(t *testing.T) {
	ctx := context.Background()
	details, _, err := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true).IssueCapabilityDetails(ctx)
	require.NoError(t, err)
	require.Len(t, details.GetOptions(), 2)

	byType := map[string]*v2.CredentialIssueOptionDescriptor{}
	for _, o := range details.GetOptions() {
		require.Equal(t, v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY, o.GetOption(),
			"both kinds are the same shape; only the secret resource type separates them")
		byType[o.GetSecretResourceTypeId()] = o
	}
	require.Contains(t, byType, serviceAccountApplicationKeyResourceType.Id)
	require.Contains(t, byType, apiTokenResourceType.Id)
	require.True(t, byType[serviceAccountApplicationKeyResourceType.Id].GetPreferred())
	require.False(t, byType[apiTokenResourceType.Id].GetPreferred())
	require.True(t, byType[serviceAccountApplicationKeyResourceType.Id].GetCustomScopesAllowed())
	require.False(t, byType[apiTokenResourceType.Id].GetCustomScopesAllowed(),
		"organization API keys carry no scopes")
}

// TestIssuanceOmitsOrgAPIKeyWithoutGrant: without the delete grant there is no
// revoke path for an organization API key, and the SDK refuses to register a
// descriptor whose secret resource type has no deleter. Advertising it anyway
// would fail connector startup, so the descriptor has to be absent too.
func TestIssuanceOmitsOrgAPIKeyWithoutGrant(t *testing.T) {
	ctx := context.Background()
	details, _, err := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), false).IssueCapabilityDetails(ctx)
	require.NoError(t, err)
	require.Len(t, details.GetOptions(), 1)
	require.Equal(t, serviceAccountApplicationKeyResourceType.Id, details.GetOptions()[0].GetSecretResourceTypeId())

	out, err := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), false).Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  "req-org-denied",
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: apiTokenResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
	})
	require.Nil(t, out)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestIssueDispatchesOnRequestedCredentialKind proves the Issue path routes on
// the requested type rather than hardcoding one arm: the same identity and the
// same API_KEY shape must reach a different Datadog endpoint per kind.
func TestIssueDispatchesOnRequestedCredentialKind(t *testing.T) {
	ctx := context.Background()
	var requests []*recordedRequest
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, &recordedRequest{method: r.Method, path: r.URL.Path})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": "org-key-id", "type": "api_keys",
				"attributes": map[string]any{"name": "c1-req-org", "key": "org-key-secret"},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true)
	out, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  "req-org",
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: apiTokenResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
	})
	require.NoError(t, err)
	require.Equal(t, apiTokenResourceType.Id, out.Secret.GetId().GetResourceType(),
		"the issued resource must come back as the kind that was requested")
	require.Equal(t, "org-key-id", out.Secret.GetId().GetResource())
	require.Len(t, out.PlaintextData, 1)
	require.Equal(t, "api_key", out.PlaintextData[0].GetName())

	mu.Lock()
	defer mu.Unlock()
	var sawOrgCreate bool
	for _, req := range requests {
		require.NotContains(t, req.path, "/service_accounts/",
			"an organization API key request must never reach the service-account application key API")
		if req.method == http.MethodPost && req.path == "/api/v2/api_keys" {
			sawOrgCreate = true
		}
	}
	require.True(t, sawOrgCreate, "the organization API key arm must call POST /api/v2/api_keys")
}

// TestIssueRejectsScopesOnOrgAPIKey: the shape allows scopes, this kind does
// not, so the arm has to fail closed rather than mint an unscoped key.
func TestIssueRejectsScopesOnOrgAPIKey(t *testing.T) {
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true)
	out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  "req-org-scoped",
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: apiTokenResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{Scopes: []string{"dashboards_read"}}.Build(),
		}.Build(),
	})
	require.Nil(t, out)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestIssueRejectsUnknownCredentialKind: an unadvertised secret resource type
// is a protocol mismatch, not a cue to fall back to the preferred arm.
func TestIssueRejectsUnknownCredentialKind(t *testing.T) {
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true)
	for _, secretType := range []string{"", "not-a-datadog-credential"} {
		out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
			IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
			RequestID:  "req-unknown",
			CredentialOptions: v2.CredentialIssueOptions_builder{
				SecretResourceTypeId: secretType,
				ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
			}.Build(),
		})
		require.Nil(t, out)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}
