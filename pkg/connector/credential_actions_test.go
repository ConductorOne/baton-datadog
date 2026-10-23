package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
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
				serialized, err := protojson.Marshal(schema)
				require.NoError(t, err)
				var restored v2.BatonActionSchema
				require.NoError(t, protojson.Unmarshal(serialized, &restored))
				require.True(t, restored.GetArguments()[2].GetIsRequired())
				require.True(t, restored.GetArguments()[2].GetStringSliceField().GetRules().GetUnique())
				require.Equal(t, nonblankScopePattern,
					restored.GetArguments()[2].GetStringSliceField().GetRules().GetItemRules().GetPattern())
			case ActionIssueServiceAccountApplicationKey:
				require.Len(t, schema.GetArguments(), 3)
				require.False(t, schema.GetArguments()[2].GetIsRequired())
			default:
				require.Len(t, schema.GetArguments(), 2)
			}
		}
	}
}

func TestPublishedCredentialScopeRulesMatchHandlerWhitespacePolicy(t *testing.T) {
	for _, required := range []bool{false, true} {
		fieldRules := issuanceScopeField(required).GetStringSliceField().GetRules()
		require.NotEmpty(t, fieldRules.GetItemRules().GetPattern())
		for _, blank := range []string{"", " ", "\t\n", "\u0085", "\u00a0", "\u1680", "\u2003", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"} {
			require.Error(t, field.ValidateRepeatedStringRules(fieldRules, []string{blank}, "scopes"),
				"published rules must reject whitespace-only scope %q", blank)
			require.Error(t, validateIssuanceScopes([]string{blank}, required),
				"provider guard must reject whitespace-only scope %q", blank)
		}
		for _, valid := range []string{"read", "  read  ", "\u200b", "\ufeff"} {
			require.NoError(t, field.ValidateRepeatedStringRules(fieldRules, []string{valid}, "scopes"),
				"published rules must preserve valid scope %q", valid)
			require.NoError(t, validateIssuanceScopes([]string{valid}, required),
				"provider guard must preserve valid scope %q", valid)
		}
		require.Error(t, field.ValidateRepeatedStringRules(fieldRules, []string{"read", "read"}, "scopes"))
	}
	require.Error(t, field.ValidateRepeatedStringRules(issuanceScopeField(true).GetStringSliceField().GetRules(), nil, "scopes"))
	require.NoError(t, field.ValidateRepeatedStringRules(issuanceScopeField(false).GetStringSliceField().GetRules(), nil, "scopes"))
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

	serviceSDK, err := connectorbuilder.NewConnector(context.Background(), &Datadog{
		wrapper: issuer.wrapper, SyncSecrets: true, SyncServiceAccountApplicationKeys: true,
	})
	require.NoError(t, err)
	encryptionConfig, _, err := (&jwk.JWKEncryptionProvider{}).GenerateKey(context.Background())
	require.NoError(t, err)
	response, err := serviceSDK.InvokeAction(context.Background(), v2.InvokeActionRequest_builder{
		Name: ActionIssueServiceAccountAccessToken, ResourceTypeId: userResourceType.Id,
		Args:              issuanceArgs(t, "sa-1", "whitespace-scope", []any{"\u2003"}),
		EncryptionConfigs: []*v2.EncryptionConfig{encryptionConfig},
	}.Build())
	require.NoError(t, err)
	require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_FAILED, response.GetStatus())
	require.Empty(t, response.GetEncryptedData())
	require.Zero(t, providerCalls, "a whitespace-only SAT scope must fail before any provider call")
}

func TestCredentialActionStatusCarriesEncryptedResultAfterPending(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePost := func() { releaseOnce.Do(func() { close(release) }) }
	var creates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			creates.Add(1)
			close(entered)
			<-release
			_, _ = w.Write([]byte(`{"data":{"id":"pending-org-id","type":"api_keys","attributes":{"key":"pending-value","name":"c1-pending-ticket"}}}`))
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	// Defer calls run in reverse order: unblock POST before Close waits for it.
	// A failed require before the explicit release must still finish the test.
	defer releasePost()
	ctx := context.Background()
	sdk, err := connectorbuilder.NewConnector(ctx, &Datadog{
		wrapper: newLifecycleTestWrapper(server.URL), SyncSecrets: true, AllowOrgAPIKeyDeletion: true,
	})
	require.NoError(t, err)
	config, privateKey, err := (&jwk.JWKEncryptionProvider{}).GenerateKey(ctx)
	require.NoError(t, err)
	invoked, err := sdk.InvokeAction(ctx, v2.InvokeActionRequest_builder{
		Name: ActionIssueOrganizationAPIKey, ResourceTypeId: userResourceType.Id,
		Args:              issuanceArgs(t, "user-1", "pending-ticket", nil),
		EncryptionConfigs: []*v2.EncryptionConfig{config}, InlineWait: durationpb.New(time.Millisecond),
	}.Build())
	require.NoError(t, err)
	require.NotEmpty(t, invoked.GetId())
	require.True(t, actions.IsInFlight(invoked.GetStatus()))
	require.Empty(t, invoked.GetEncryptedData())
	require.NotContains(t, invoked.GetResponse().String(), "pending-value")
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider create did not start")
	}
	releasePost()
	var settled *v2.GetActionStatusResponse
	require.Eventually(t, func() bool {
		var statusErr error
		settled, statusErr = sdk.GetActionStatus(ctx, v2.GetActionStatusRequest_builder{Id: invoked.GetId()}.Build())
		return statusErr == nil && settled.GetStatus() == v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE
	}, 3*time.Second, 10*time.Millisecond)
	require.Len(t, settled.GetEncryptedData(), 1)
	resource, ok := actions.GetResourceFieldArg(settled.GetResponse(), "issued_resource")
	require.True(t, ok)
	require.Equal(t, apiTokenResourceType.Id, resource.GetId().GetResourceType())
	require.Equal(t, "pending-org-id", resource.GetId().GetResource())
	require.NotContains(t, settled.GetResponse().String(), "pending-value")
	plaintext, err := (&jwk.JWKEncryptionProvider{}).Decrypt(ctx, settled.GetEncryptedData()[0], privateKey)
	require.NoError(t, err)
	require.Equal(t, "api_key_v2", plaintext.GetSchema())
	require.JSONEq(t, `{"key_value":"pending-value","provider":"datadog","key_id":"pending-org-id","header_name":"DD-API-KEY"}`, string(plaintext.GetBytes()))
	require.EqualValues(t, 1, creates.Load())
}
