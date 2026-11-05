package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-datadog/pkg/multipass"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// identityArg builds the identity_id argument the way C1 sends a ResourceId.
func identityArg(t *testing.T, resourceType, resource string) *structpb.Value {
	t.Helper()
	v, err := structpb.NewValue(map[string]any{
		"resource_type": resourceType,
		"resource":      resource,
	})
	require.NoError(t, err)
	return v
}

// newCredentialIssueActionRegistry registers the connector's global actions and
// returns the manager, so the schemas under test are the registered ones.
func newCredentialIssueActionRegistry(t *testing.T, d *Datadog) *actions.ActionManager {
	t.Helper()
	mgr := actions.NewActionManager(context.Background())
	require.NoError(t, d.GlobalActions(context.Background(), mgr))
	return mgr
}

// fullGrants is a Datadog with every credential grant set.
func fullGrants(serverURL string) *Datadog {
	return &Datadog{
		wrapper:                           newLifecycleTestWrapper(serverURL),
		baseURL:                           testAPIBaseURL,
		SyncSecrets:                       true,
		AllowOrgAPIKeyDeletion:            true,
		SyncServiceAccountApplicationKeys: true,
	}
}

// TestCredentialIssueActionSchemas: every credential-issue action carries the
// SDK's fixed arguments, and only the application key adds the one provider
// input Datadog has.
func TestCredentialIssueActionSchemas(t *testing.T) {
	ctx := context.Background()
	mgr := newCredentialIssueActionRegistry(t, fullGrants("http://127.0.0.1:1"))

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
		case actions.ArgIdentityID:
			require.True(t, a.GetIsRequired(), "%s is required", a.GetName())
			// C1 reads the issuer's identity resource type from here.
			require.Equal(t, []string{userResourceType.Id},
				a.GetResourceIdField().GetRules().GetAllowedResourceTypeIds(),
				"identity_id must allow exactly the issuer's identity resource type")
		case actions.ArgRequestID:
			require.True(t, a.GetIsRequired(), "%s is required", a.GetName())
		case actionArgScopes:
			require.False(t, a.GetIsRequired(), "scopes are optional")
			require.NotNil(t, a.GetStringSliceField(), "scopes are a string slice")
		}
	}
}

// TestOrgAPIKeyActionOutput is the payload contract: the response names the key
// the fake provider minted, and the plaintext is the api_key_v2 document with
// the values the connector resolved, not merely valid JSON.
func TestOrgAPIKeyActionOutput(t *testing.T) {
	ctx := context.Background()

	const keyID = "org-key-id"
	var sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			sawPath = r.URL.Path
			_, _ = w.Write([]byte(`{"data":{"id":"` + keyID + `","type":"api_keys","attributes":{"name":"c1-req-act","key":"org-key-secret"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	args, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "req-act"})
	require.NoError(t, err)
	args.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, testServiceAccountID)

	response, plaintext, _, err := u.issueOrganizationAPIKeyAction(ctx, args)
	require.NoError(t, err)
	require.Equal(t, "/api/v2/api_keys", sawPath)
	require.Len(t, plaintext, 1)

	// The response names the key the provider actually minted.
	require.Equal(t, keyID, response.GetFields()[actions.ReturnSecretResourceID].GetStringValue())
	// And it does not claim an expiry neither kind has.
	require.NotContains(t, response.GetFields(), actions.ReturnExpiresAt)

	// The plaintext is the declared type, under the declared name, carrying the
	// values the connector resolved.
	require.Equal(t, datadogAPIKeyFieldName, plaintext[0].GetName())
	descriptor := organizationAPIKeyDescriptor()
	require.Equal(t, descriptor.GetOutput().GetContentType(), plaintext[0].GetSchema())

	var payload multipass.APIKeyV2
	require.NoError(t, json.Unmarshal(plaintext[0].GetBytes(), &payload))
	require.Equal(t, "org-key-secret", payload.KeyValue)
	require.Equal(t, keyID, payload.KeyID)
	require.Equal(t, datadogProviderName, payload.Provider)
	require.Equal(t, testAPIBaseURL, payload.BaseURL)
	require.Equal(t, datadogAPIKeyHeaderName, payload.HeaderName)
	require.Empty(t, payload.Scopes, "an organization key carries no scopes")
}

// TestOrgAPIKeyActionOutputPassesValidation rebuilds the secret resource the way
// C1 does and runs the SDK's validator over it.
func TestOrgAPIKeyActionOutputPassesValidation(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"data":{"id":"org-key-id","type":"api_keys","attributes":{"name":"c1-req-v","key":"org-key-secret"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	identityID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}
	args, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "req-v"})
	require.NoError(t, err)
	args.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, testServiceAccountID)

	response, plaintext, _, err := u.issueOrganizationAPIKeyAction(ctx, args)
	require.NoError(t, err)

	descriptor := organizationAPIKeyDescriptor()
	secret, err := actions.CredentialIssueResource(response, identityID, descriptor)
	require.NoError(t, err)
	require.NoError(t, connectorbuilder.ValidateIssuedCredential(identityID, nil,
		&connectorbuilder.CredentialIssueOutput{
			Secret:        secret,
			PlaintextData: plaintext,
			ResourceMode:  descriptor.GetResourceMode(),
		}, descriptor))
}

// TestCredentialIssueActionsGatedOnOperatorGrants: the organization issuer needs
// both SyncSecrets and the delete grant, because the deletable syncer that
// revoke needs is registered only under SyncSecrets.
func TestCredentialIssueActionsGatedOnOperatorGrants(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name          string
		syncSecrets   bool
		allowDeletion bool
		wantOrg       bool
		wantApp       bool
	}{
		{name: "no grants", wantOrg: false, wantApp: false},
		{name: "deletion grant without SyncSecrets", syncSecrets: false, allowDeletion: true, wantOrg: false, wantApp: false},
		{name: "SyncSecrets only", syncSecrets: true, allowDeletion: false, wantOrg: false, wantApp: false},
		{name: "SyncSecrets and deletion grant", syncSecrets: true, allowDeletion: true, wantOrg: true, wantApp: false},
		{name: "application key grant only", syncSecrets: true, wantOrg: false, wantApp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Datadog{
				wrapper:                           newLifecycleTestWrapper("http://127.0.0.1:1"),
				baseURL:                           testAPIBaseURL,
				SyncSecrets:                       tc.syncSecrets,
				AllowOrgAPIKeyDeletion:            tc.allowDeletion,
				SyncServiceAccountApplicationKeys: tc.wantApp,
			}
			mgr := newCredentialIssueActionRegistry(t, d)
			schemas, _, err := mgr.ListActionSchemas(ctx, "")
			require.NoError(t, err)
			byName := schemaByName(schemas)

			if tc.wantOrg {
				require.Contains(t, byName, ActionIssueOrganizationAPIKeyAction)
			} else {
				require.NotContains(t, byName, ActionIssueOrganizationAPIKeyAction)
			}
			if tc.wantApp {
				require.Contains(t, byName, ActionIssueServiceAccountApplicationKeyAction)
			} else {
				require.NotContains(t, byName, ActionIssueServiceAccountApplicationKeyAction)
			}
		})
	}
}

// TestCredentialIssueActionFailures covers the handler-level refusals: the
// argument checks and the duplicate guard, plus the service-account re-check.
func TestCredentialIssueActionFailures(t *testing.T) {
	ctx := context.Background()

	// A provider that reports no existing key and mints one, and answers the
	// service-account lookup according to the id asked for.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/human-1":
			_, _ = w.Write([]byte(`{"data":{"id":"human-1","type":"users","attributes":{"service_account":false}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":["should not mint"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	orgU := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	appU := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false, true, testAPIBaseURL)

	for _, tc := range []struct {
		name     string
		call     func(*structpb.Struct) error
		args     func(t *testing.T) *structpb.Struct
		wantCode codes.Code
	}{
		{
			name: "org: missing identity_id",
			call: func(a *structpb.Struct) error {
				_, _, _, err := orgU.issueOrganizationAPIKeyAction(ctx, a)
				return err
			},
			args: func(t *testing.T) *structpb.Struct {
				a, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "r"})
				require.NoError(t, err)
				return a
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "org: empty identity_id resource",
			call: func(a *structpb.Struct) error {
				_, _, _, err := orgU.issueOrganizationAPIKeyAction(ctx, a)
				return err
			},
			args: func(t *testing.T) *structpb.Struct {
				a, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "r"})
				require.NoError(t, err)
				a.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, "")
				return a
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "org: missing request_id",
			call: func(a *structpb.Struct) error {
				_, _, _, err := orgU.issueOrganizationAPIKeyAction(ctx, a)
				return err
			},
			args: func(t *testing.T) *structpb.Struct {
				a, err := structpb.NewStruct(map[string]any{})
				require.NoError(t, err)
				a.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, testServiceAccountID)
				return a
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "org: empty request_id",
			call: func(a *structpb.Struct) error {
				_, _, _, err := orgU.issueOrganizationAPIKeyAction(ctx, a)
				return err
			},
			args: func(t *testing.T) *structpb.Struct {
				a, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: ""})
				require.NoError(t, err)
				a.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, testServiceAccountID)
				return a
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "app: identity is not a service account",
			call: func(a *structpb.Struct) error {
				_, _, _, err := appU.issueServiceAccountApplicationKeyAction(ctx, a)
				return err
			},
			args: func(t *testing.T) *structpb.Struct {
				a, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "r"})
				require.NoError(t, err)
				a.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, "human-1")
				return a
			},
			wantCode: codes.InvalidArgument,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(tc.args(t))
			require.Error(t, err)
			require.Equal(t, tc.wantCode, status.Code(err), "error was: %v", err)
		})
	}
}

// TestCredentialIssueActionRefusesDuplicateRequest: a repeated request is
// refused rather than minting a second key, and nothing is created.
func TestCredentialIssueActionRefusesDuplicateRequest(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[{"id":"old","type":"api_keys","attributes":{"name":"c1-req-dup"}}]}`))
		case r.Method == http.MethodPost:
			t.Error("a duplicate request must not mint a key")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	args, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "req-dup"})
	require.NoError(t, err)
	args.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, testServiceAccountID)

	_, _, _, err = u.issueOrganizationAPIKeyAction(ctx, args)
	require.Error(t, err)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}

// TestAppKeyActionOutput: the response names the minted key, the plaintext
// carries the values the connector resolved including the provider-reported
// scopes, and the request reached that service account's own path with the
// scopes asked for. The identity is a second service account, so a handler that
// ignored identity_id and used a default would be caught here.
func TestAppKeyActionOutput(t *testing.T) {
	ctx := context.Background()

	const (
		keyID            = "app-key-id"
		otherServiceAcct = "sa-2"
	)
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, &requests, r)
		w.Header().Set("Content-Type", "application/json")
		saPath := "/api/v2/service_accounts/" + "sa-2" + "/application_keys"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-2":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-2","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == saPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == saPath:
			_, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"data":{"id":"` + keyID + `","type":"application_keys","attributes":{"key":"app-secret","name":"c1-req-app","scopes":["logs_read"]}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false, true, testAPIBaseURL)
	args, err := structpb.NewStruct(map[string]any{actions.ArgRequestID: "req-app"})
	require.NoError(t, err)
	args.Fields[actions.ArgIdentityID] = identityArg(t, userResourceType.Id, "sa-2")
	scopesVal, err := structpb.NewValue([]any{"logs_read"})
	require.NoError(t, err)
	args.Fields[actionArgScopes] = scopesVal

	response, plaintext, _, err := u.issueServiceAccountApplicationKeyAction(ctx, args)
	require.NoError(t, err)

	require.Equal(t, keyID, response.GetFields()[actions.ReturnSecretResourceID].GetStringValue())
	require.NotContains(t, response.GetFields(), actions.ReturnExpiresAt)

	require.Equal(t, datadogApplicationKeyFieldName, plaintext[0].GetName())
	descriptor := serviceAccountApplicationKeyDescriptor()
	require.Equal(t, descriptor.GetOutput().GetContentType(), plaintext[0].GetSchema())

	var payload multipass.APIKeyV2
	require.NoError(t, json.Unmarshal(plaintext[0].GetBytes(), &payload))
	require.Equal(t, "app-secret", payload.KeyValue)
	require.Equal(t, keyID, payload.KeyID)
	require.Equal(t, datadogProviderName, payload.Provider)
	require.Equal(t, testAPIBaseURL, payload.BaseURL)
	require.Equal(t, datadogApplicationKeyHeaderName, payload.HeaderName)
	require.Equal(t, []string{"logs_read"}, payload.Scopes)

	// The request went to sa-2's path and asked for the scopes given.
	var sawPost bool
	for _, rec := range snapshotRequests(&requests) {
		if rec.method == http.MethodPost {
			sawPost = true
			require.Equal(t, "/api/v2/service_accounts/sa-2/application_keys", rec.path)
			require.Contains(t, rec.body, "logs_read", "the request must carry the scopes asked for")
		}
		require.NotContains(t, rec.path, testServiceAccountID,
			"the handler must target the identity the request named, not a default")
	}
	require.True(t, sawPost)
}
