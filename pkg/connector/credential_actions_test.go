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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func issuanceArgs(t *testing.T, userID string, requestID string, scopes any) *structpb.Struct {
	t.Helper()
	values := map[string]any{
		"user_id":    map[string]any{"resource_type_id": userResourceType.Id, "resource_id": userID},
		"request_id": requestID,
	}
	if scopes != nil {
		values["scopes"] = scopes
	}
	args, err := structpb.NewStruct(values)
	require.NoError(t, err)
	return args
}

func TestCredentialActionSchemasFollowPermissionGates(t *testing.T) {
	for _, tc := range []struct {
		org, service bool
		want         []string
	}{
		{false, false, nil},
		{true, false, []string{ActionIssueOrganizationAPIKey}},
		{false, true, []string{ActionIssueServiceAccountApplicationKey, ActionIssueServiceAccountAccessToken}},
		{true, true, []string{ActionIssueOrganizationAPIKey, ActionIssueServiceAccountApplicationKey, ActionIssueServiceAccountAccessToken}},
	} {
		manager := actions.NewActionManager(context.Background())
		registry, err := manager.GetTypeRegistry(context.Background(), userResourceType.Id)
		require.NoError(t, err)
		issuer := newCredentialUserBuilder(nil, tc.org, tc.service)
		require.NoError(t, issuer.ResourceActions(context.Background(), registry))
		schemas, _, err := manager.ListActionSchemas(context.Background(), userResourceType.Id)
		require.NoError(t, err)
		byName := schemaByName(schemas)
		require.Contains(t, byName, ActionUpdateUser)
		for _, name := range []string{ActionIssueOrganizationAPIKey, ActionIssueServiceAccountApplicationKey, ActionIssueServiceAccountAccessToken} {
			want := false
			for _, expected := range tc.want {
				if name == expected {
					want = true
				}
			}
			if !want {
				require.NotContains(t, byName, name)
				continue
			}
			schema := byName[name]
			require.Equal(t, userResourceType.Id, schema.GetResourceTypeId())
			require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC}, schema.GetActionType())
			require.Len(t, schema.GetReturnTypes(), 3)
			require.Equal(t, "issued_resource", schema.GetReturnTypes()[1].GetName())
			require.True(t, schema.GetReturnTypes()[2].GetIsSecret())
			switch name {
			case ActionIssueServiceAccountAccessToken:
				require.Len(t, schema.GetArguments(), 3)
				require.True(t, schema.GetArguments()[2].GetIsRequired())
				require.Equal(t, uint64(1), schema.GetArguments()[2].GetStringSliceField().GetRules().GetMinItems())
			case ActionIssueServiceAccountApplicationKey:
				require.Len(t, schema.GetArguments(), 3)
				require.False(t, schema.GetArguments()[2].GetIsRequired())
			default:
				require.Len(t, schema.GetArguments(), 2)
			}
		}
	}
}

func TestCredentialActionsRejectInvalidInputsBeforeProviderCall(t *testing.T) {
	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		t.Errorf("provider called for invalid input: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, true)
	for _, tc := range []struct {
		name, kind string
		args       *structpb.Struct
	}{
		{"missing SAT scopes", serviceAccountAccessTokenResourceType.Id, issuanceArgs(t, "sa-1", "valid", nil)},
		{"blank SAT scope", serviceAccountAccessTokenResourceType.Id, issuanceArgs(t, "sa-1", "valid", []any{"\u00a0"})},
		{"duplicate SAT scope", serviceAccountAccessTokenResourceType.Id, issuanceArgs(t, "sa-1", "valid", []any{"read", "read"})},
		{"malformed app scopes", serviceAccountApplicationKeyResourceType.Id, issuanceArgs(t, "sa-1", "valid", "read")},
		{"org scopes", apiTokenResourceType.Id, issuanceArgs(t, "user-1", "valid", []any{"read"})},
		{"invalid request ID", apiTokenResourceType.Id, issuanceArgs(t, "user-1", "bad/request", nil)},
		{"empty user", apiTokenResourceType.Id, issuanceArgs(t, "", "valid", nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, plaintext, _, err := issuer.issueAction(tc.kind)(context.Background(), tc.args)
			require.Nil(t, result)
			require.Nil(t, plaintext)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	require.Zero(t, providerCalls)

	// The SDK rejects a missing encryption recipient before invoking a secret
	// handler, so no provider request is possible in this case either.
	sdk, err := connectorbuilder.NewConnector(context.Background(), &Datadog{wrapper: issuer.wrapper, SyncSecrets: true, AllowOrgAPIKeyDeletion: true})
	require.NoError(t, err)
	_, err = sdk.InvokeAction(context.Background(), v2.InvokeActionRequest_builder{
		Name: ActionIssueOrganizationAPIKey, ResourceTypeId: userResourceType.Id,
		Args: issuanceArgs(t, "user-1", "valid", nil),
	}.Build())
	require.Error(t, err)
	require.Zero(t, providerCalls)
}
