package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// identityArg builds the identity_id argument the way C1 sends a ResourceId:
// as a struct with the resource type and the resource id.
func identityArg(t *testing.T, resourceType, resource string) *structpb.Value {
	t.Helper()
	v, err := structpb.NewValue(map[string]any{
		"resource_type": resourceType,
		"resource":      resource,
	})
	if err != nil {
		t.Fatalf("build identity arg: %v", err)
	}
	return v
}

// credentialIssueActionArgsFor builds the argument struct for a credential-issue
// action invocation.
func credentialIssueActionArgsFor(t *testing.T, resourceType, resource, requestID string) *structpb.Struct {
	t.Helper()
	fields := map[string]any{
		actions.ArgRequestID: requestID,
	}
	args, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	args.Fields[actions.ArgIdentityID] = identityArg(t, resourceType, resource)
	return args
}

// newCredentialIssueActionRegistry registers the connector's global actions and
// returns the manager, so the schemas under test are the registered ones.
func newCredentialIssueActionRegistry(t *testing.T, d *Datadog) *actions.ActionManager {
	t.Helper()
	mgr := actions.NewActionManager(context.Background())
	require.NoError(t, d.GlobalActions(context.Background(), mgr))
	return mgr
}

// TestCredentialIssueActionSchemas: every credential-issue action carries the
// SDK's fixed arguments, and only the application key adds the one provider
// input Datadog has.
func TestCredentialIssueActionSchemas(t *testing.T) {
	ctx := context.Background()
	mgr := newCredentialIssueActionRegistry(t, &Datadog{
		wrapper:                           newLifecycleTestWrapper("http://127.0.0.1:1"),
		baseURL:                           testAPIBaseURL,
		SyncSecrets:                       true,
		AllowOrgAPIKeyDeletion:            true,
		SyncServiceAccountApplicationKeys: true,
	})

	schemas, _, err := mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName := schemaByName(schemas)

	orgSchema, ok := byName[ActionIssueOrganizationAPIKeyAction]
	require.True(t, ok, "the organization key action must be registered")
	require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_CREDENTIAL_ISSUE}, orgSchema.GetActionType())
	require.NotNil(t, orgSchema.GetCredentialIssue(), "the schema carries the descriptor")
	requireArgs(t, orgSchema, actions.ArgIdentityID, actions.ArgRequestID)

	appSchema, ok := byName[ActionIssueServiceAccountApplicationKeyAction]
	require.True(t, ok, "the application key action must be registered")
	require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_CREDENTIAL_ISSUE}, appSchema.GetActionType())
	require.NotNil(t, appSchema.GetCredentialIssue())
	requireArgs(t, appSchema, actions.ArgIdentityID, actions.ArgRequestID, actionArgScopes)
}

// requireArgs asserts the schema declares exactly these argument names, with the
// SDK's fixed ones required.
func requireArgs(t *testing.T, schema *v2.BatonActionSchema, want ...string) {
	t.Helper()
	var got []string
	for _, a := range schema.GetArguments() {
		got = append(got, a.GetName())
	}
	require.ElementsMatch(t, want, got)
	for _, a := range schema.GetArguments() {
		switch a.GetName() {
		case actions.ArgIdentityID, actions.ArgRequestID:
			require.True(t, a.GetIsRequired(), "%s is required", a.GetName())
		case actionArgScopes:
			require.False(t, a.GetIsRequired(), "scopes are optional")
			require.NotNil(t, a.GetStringSliceField(), "scopes are a string slice")
		}
	}
}

// TestOrgAPIKeyActionOutputPassesValidation runs the handler and puts its result
// through the same reconstruction and validation C1 performs.
func TestOrgAPIKeyActionOutputPassesValidation(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"org-key-id","type":"api_keys","attributes":{"name":"c1-req-act","key":"org-key-secret"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	identityID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}
	args := credentialIssueActionArgsFor(t, userResourceType.Id, testServiceAccountID, "req-act")

	response, plaintext, _, err := u.issueOrganizationAPIKeyAction(ctx, args)
	require.NoError(t, err)
	require.Len(t, plaintext, 1)

	descriptor := organizationAPIKeyDescriptor()
	secret, err := actions.CredentialIssueResource(response, identityID, descriptor)
	require.NoError(t, err, "the response must carry a secret_resource_id the SDK can rebuild")

	require.NoError(t, connectorbuilder.ValidateIssuedCredential(identityID, nil,
		&connectorbuilder.CredentialIssueOutput{
			Secret:        secret,
			PlaintextData: plaintext,
			ResourceMode:  descriptor.GetResourceMode(),
		}, descriptor))

	// The plaintext is the declared type under the declared name.
	require.Equal(t, datadogAPIKeyFieldName, plaintext[0].GetName())
	require.Equal(t, descriptor.GetOutput().GetContentType(), plaintext[0].GetSchema())
}

// TestAppKeyActionOutputPassesValidation is the same for the application key,
// which additionally carries scopes.
func TestAppKeyActionOutputPassesValidation(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":{"id":"app-key-id","type":"application_keys","attributes":{"key":"app-secret","name":"c1-req-act","scopes":["logs_read"]}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false, true, testAPIBaseURL)
	identityID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}
	args := credentialIssueActionArgsFor(t, userResourceType.Id, testServiceAccountID, "req-act")
	scopes, err := structpb.NewValue([]any{"logs_read"})
	require.NoError(t, err)
	args.Fields[actionArgScopes] = scopes

	response, plaintext, _, err := u.issueServiceAccountApplicationKeyAction(ctx, args)
	require.NoError(t, err)

	descriptor := serviceAccountApplicationKeyDescriptor()
	secret, err := actions.CredentialIssueResource(response, identityID, descriptor)
	require.NoError(t, err)

	require.NoError(t, connectorbuilder.ValidateIssuedCredential(identityID, nil,
		&connectorbuilder.CredentialIssueOutput{
			Secret:        secret,
			PlaintextData: plaintext,
			ResourceMode:  descriptor.GetResourceMode(),
		}, descriptor))

	require.Equal(t, datadogApplicationKeyFieldName, plaintext[0].GetName())
	require.Equal(t, descriptor.GetOutput().GetContentType(), plaintext[0].GetSchema())
}

// TestCredentialIssueActionsGatedOnOperatorGrants: an issuer whose revoke path
// the connector lacks must not be advertised as an action either.
func TestCredentialIssueActionsGatedOnOperatorGrants(t *testing.T) {
	ctx := context.Background()

	mgr := newCredentialIssueActionRegistry(t, &Datadog{wrapper: newLifecycleTestWrapper("http://127.0.0.1:1"), baseURL: testAPIBaseURL})
	schemas, _, err := mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName := schemaByName(schemas)
	require.NotContains(t, byName, ActionIssueOrganizationAPIKeyAction)
	require.NotContains(t, byName, ActionIssueServiceAccountApplicationKeyAction)

	mgr = newCredentialIssueActionRegistry(t, &Datadog{
		wrapper: newLifecycleTestWrapper("http://127.0.0.1:1"), baseURL: testAPIBaseURL, AllowOrgAPIKeyDeletion: true,
	})
	schemas, _, err = mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName = schemaByName(schemas)
	require.Contains(t, byName, ActionIssueOrganizationAPIKeyAction)
	require.NotContains(t, byName, ActionIssueServiceAccountApplicationKeyAction)
}
