package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	filippoage "filippo.io/age"
	"github.com/conductorone/baton-datadog/pkg/multipass"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	ageprovider "github.com/conductorone/baton-sdk/pkg/crypto/providers/age"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// newVendingDatadog builds a Datadog whose GlobalActions register the prototype
// actions, with both operator grants set so both register.
func newVendingDatadog(serverURL string) *Datadog {
	return &Datadog{
		wrapper:                           newLifecycleTestWrapper(serverURL),
		baseURL:                           testAPIBaseURL,
		SyncSecrets:                       true,
		AllowOrgAPIKeyDeletion:            true,
		SyncServiceAccountApplicationKeys: true,
	}
}

func newVendingRegistry(t *testing.T) *actions.ActionManager {
	t.Helper()
	return actions.NewActionManager(context.Background())
}

// TestVendingActionsRegisterWithTypedSecretReturn: each schema declares exactly
// the secret Field its Issue counterpart declares, and the public returns are
// identifiers only. This is the contract that lets C1 show and revoke a vended
// key without ever seeing it.
func TestVendingActionsRegisterWithTypedSecretReturn(t *testing.T) {
	ctx := context.Background()
	mgr := newVendingRegistry(t)
	require.NoError(t, newVendingDatadog("http://127.0.0.1:1").GlobalActions(ctx, mgr))

	schemas, _, err := mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName := schemaByName(schemas)

	_, ok := byName[ActionIssueOrganizationAPIKey]
	require.True(t, ok, "the organization key action must be registered")
	appSchema, ok := byName[ActionIssueServiceAccountApplicationKey]
	require.True(t, ok, "the application key action must be registered")

	// The required arguments are the ones the brief specifies.
	argNames := map[string]bool{}
	for _, a := range appSchema.GetArguments() {
		argNames[a.GetName()] = a.GetIsRequired()
	}
	require.True(t, argNames["request_id"], "request_id is required")
	require.True(t, argNames["service_account_id"], "service_account_id is required")
	required, ok := argNames["scopes"]
	require.True(t, ok, "scopes is declared")
	require.False(t, required, "scopes is optional")
}

// TestVendingActionsDeclareTheSameSecretReturnAsIssue is the assertion the
// prototype exists to make: the action's secret return is the same descriptor
// Field the Issue path advertises.
func TestVendingActionsDeclareTheSameSecretReturnAsIssue(t *testing.T) {
	ctx := context.Background()
	mgr := newVendingRegistry(t)
	require.NoError(t, newVendingDatadog("http://127.0.0.1:1").GlobalActions(ctx, mgr))

	schemas, _, err := mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName := schemaByName(schemas)

	for _, tc := range []struct {
		action string
		want   *configv1.Field
	}{
		{ActionIssueOrganizationAPIKey, organizationAPIKeyOutput()},
		{ActionIssueServiceAccountApplicationKey, serviceAccountApplicationKeyOutput()},
	} {
		schema := byName[tc.action]
		require.NotNil(t, schema, tc.action)

		var secret *configv1.Field
		var publicNames []string
		for _, f := range schema.GetReturnTypes() {
			if f.GetIsSecret() {
				require.Nil(t, secret, "%s must declare exactly one secret return", tc.action)
				secret = f
				continue
			}
			publicNames = append(publicNames, f.GetName())
		}
		require.NotNil(t, secret, "%s must declare a secret return", tc.action)

		require.Equal(t, tc.want.GetName(), secret.GetName())
		require.Equal(t, tc.want.GetContentType(), secret.GetContentType())
		require.Equal(t, tc.want.GetTags(), secret.GetTags())
		require.NotNil(t, secret.GetStringField(), "the secret return is a string field")
		require.Equal(t, multipass.ContentType(multipass.TypeAPIKeyV2), secret.GetContentType())

		// The application key also names its service account, because
		// applicationKeyBuilder.Delete needs both halves.
		wantPublic := []string{actionPublicKeyID, actionPublicSecretResourceTypeID, actionPublicSecretResourceID}
		if tc.action == ActionIssueServiceAccountApplicationKey {
			wantPublic = append(wantPublic, actionPublicParentResourceTypeID, actionPublicParentResourceID)
		}
		require.ElementsMatch(t, wantPublic, publicNames)
	}
}

// TestVendingActionsGatedOnOperatorGrants: an action that could mint a
// credential the connector cannot revoke must not be advertised.
func TestVendingActionsGatedOnOperatorGrants(t *testing.T) {
	ctx := context.Background()

	// No grants: no vending actions at all.
	mgr := newVendingRegistry(t)
	d := &Datadog{wrapper: newLifecycleTestWrapper("http://127.0.0.1:1"), baseURL: testAPIBaseURL}
	require.NoError(t, d.GlobalActions(ctx, mgr))
	schemas, _, err := mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName := schemaByName(schemas)
	require.NotContains(t, byName, ActionIssueOrganizationAPIKey)
	require.NotContains(t, byName, ActionIssueServiceAccountApplicationKey)

	// Org grant only: just the organization action.
	mgr = newVendingRegistry(t)
	d = &Datadog{wrapper: newLifecycleTestWrapper("http://127.0.0.1:1"), baseURL: testAPIBaseURL, AllowOrgAPIKeyDeletion: true}
	require.NoError(t, d.GlobalActions(ctx, mgr))
	schemas, _, err = mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName = schemaByName(schemas)
	require.Contains(t, byName, ActionIssueOrganizationAPIKey)
	require.NotContains(t, byName, ActionIssueServiceAccountApplicationKey)

	// Application key grant only: just the application action.
	mgr = newVendingRegistry(t)
	d = &Datadog{
		wrapper:                           newLifecycleTestWrapper("http://127.0.0.1:1"),
		baseURL:                           testAPIBaseURL,
		SyncSecrets:                       true,
		SyncServiceAccountApplicationKeys: true,
	}
	require.NoError(t, d.GlobalActions(ctx, mgr))
	schemas, _, err = mgr.ListActionSchemas(ctx, "")
	require.NoError(t, err)
	byName = schemaByName(schemas)
	require.Contains(t, byName, ActionIssueServiceAccountApplicationKey)
	require.NotContains(t, byName, ActionIssueOrganizationAPIKey)
}

// TestVendingActionVendsThroughTheActionManager drives the real action manager,
// so the secret path is exercised end to end: the handler returns one
// PlaintextData under the declared name, and the public response carries the
// identifiers and never the key.
func TestVendingActionVendsThroughTheActionManager(t *testing.T) {
	ctx := context.Background()

	// A provider that mints one key and reports no existing one.
	var posted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			posted = true
			_, _ = w.Write([]byte(`{"data":{"id":"vend-key-id","type":"api_keys","attributes":{"name":"c1-req-vend","key":"vend-secret"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	mgr := newVendingRegistry(t)
	require.NoError(t, newVendingDatadog(server.URL).GlobalActions(ctx, mgr))

	args, err := structpb.NewStruct(map[string]any{actionArgRequestID: "req-vend"})
	require.NoError(t, err)

	// A real age recipient, because the manager refuses secret results without
	// one and the ciphertext path is part of what this prototype is proving.
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	configs := []*v2.EncryptionConfig{
		v2.EncryptionConfig_builder{
			Provider:           ageprovider.EncryptionProviderAge,
			AgeRecipientConfig: v2.EncryptionConfig_AgeRecipientConfig_builder{Recipient: identity.Recipient().String()}.Build(),
		}.Build(),
	}

	_, actionStatus, response, encrypted, _, err := mgr.InvokeActionWithWaitAndEncryption(
		ctx, ActionIssueOrganizationAPIKey, "", args, time.Second, configs)
	require.NoError(t, err)
	require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE, actionStatus)
	require.True(t, posted, "the action must mint a key at the provider")

	require.Equal(t, "vend-key-id", response.GetFields()[actionPublicKeyID].GetStringValue())
	require.Equal(t, deletableAPITokenResourceType.Id,
		response.GetFields()[actionPublicSecretResourceTypeID].GetStringValue())
	require.Equal(t, "vend-key-id", response.GetFields()[actionPublicSecretResourceID].GetStringValue())
	require.NotContains(t, response.GetFields(), datadogAPIKeyFieldName,
		"the key must not appear in the public response")

	// The key left as ciphertext. The secret return's name was asserted with the
	// schema above; here the point is that ciphertext arrived and holds no
	// plaintext.
	require.Len(t, encrypted, 1, "the one secret return must be encrypted")
	require.Equal(t, datadogAPIKeyFieldName, encrypted[0].GetName())
	require.NotContains(t, string(mustCiphertext(t, encrypted)), "vend-secret",
		"the ciphertext must not contain the plaintext key")
}

// mustCiphertext returns the encrypted bytes of the single ciphertext entry.
func mustCiphertext(t *testing.T, encrypted []*v2.EncryptedData) []byte {
	t.Helper()
	require.NotEmpty(t, encrypted)
	require.NotEmpty(t, encrypted[0].GetEncryptedBytes())
	return encrypted[0].GetEncryptedBytes()
}

// TestVendingActionRefusesDuplicateRequestID: Datadog cannot re-issue plaintext
// for an existing key, so a repeated request is refused rather than minting a
// second key.
func TestVendingActionRefusesDuplicateRequestID(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			// An existing key whose name matches the request.
			_, _ = w.Write([]byte(`{"data":[{"id":"old","type":"api_keys","attributes":{"name":"c1-req-dup"}}]}`))
		case r.Method == http.MethodPost:
			t.Error("the action must not mint a key when one already exists for the request")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unexpected"]}`))
		}
	}))
	defer server.Close()

	builder := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)
	args, err := structpb.NewStruct(map[string]any{actionArgRequestID: "req-dup"})
	require.NoError(t, err)

	_, _, _, err = builder.issueOrganizationAPIKeyAction(ctx, args)
	require.Error(t, err)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}

// TestVendingAppKeyReturnsTheIDsDeleteTakes: the response's identifiers have to
// be exactly the pair applicationKeyBuilder.Delete consumes -- the bare key id as
// resourceID, the service account as parentResourceID -- or C1's revoke would
// look up a key that does not exist. This drives the real Delete against a
// provider that only answers on that path.
func TestVendingAppKeyReturnsTheIDsDeleteTakes(t *testing.T) {
	ctx := context.Background()

	const handle = "app-key-handle"
	appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"

	var deletedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":{"id":"` + handle + `","type":"application_keys","attributes":{"key":"app-secret","name":"c1-req-ids"}}}`))
		case r.Method == http.MethodDelete:
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	mgr := newVendingRegistry(t)
	require.NoError(t, newVendingDatadog(server.URL).GlobalActions(ctx, mgr))

	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	configs := []*v2.EncryptionConfig{
		v2.EncryptionConfig_builder{
			Provider:           ageprovider.EncryptionProviderAge,
			AgeRecipientConfig: v2.EncryptionConfig_AgeRecipientConfig_builder{Recipient: identity.Recipient().String()}.Build(),
		}.Build(),
	}

	args, err := structpb.NewStruct(map[string]any{
		actionArgRequestID:        "req-ids",
		actionArgServiceAccountID: testServiceAccountID,
	})
	require.NoError(t, err)
	_, _, response, _, _, err := mgr.InvokeActionWithWaitAndEncryption(
		ctx, ActionIssueServiceAccountApplicationKey, "", args, time.Second, configs)
	require.NoError(t, err)

	// Build the resource IDs exactly as C1 would from the response.
	resourceID := &v2.ResourceId{
		ResourceType: response.GetFields()[actionPublicSecretResourceTypeID].GetStringValue(),
		Resource:     response.GetFields()[actionPublicSecretResourceID].GetStringValue(),
	}
	parent := &v2.ResourceId{
		ResourceType: response.GetFields()[actionPublicParentResourceTypeID].GetStringValue(),
		Resource:     response.GetFields()[actionPublicParentResourceID].GetStringValue(),
	}

	// The pair has to be the bare key id plus the service account, not a
	// composite id and no parent.
	require.Equal(t, serviceAccountApplicationKeyResourceType.Id, resourceID.GetResourceType())
	require.Equal(t, handle, resourceID.GetResource(), "resourceID must be the bare key id")
	require.Equal(t, userResourceType.Id, parent.GetResourceType())
	require.Equal(t, testServiceAccountID, parent.GetResource())

	// And Delete accepts exactly that pair, reaching the provider path that only
	// exists for this key under its service account.
	_, err = newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL)).Delete(ctx, resourceID, parent)
	require.NoError(t, err)
	require.Equal(t, appKeysPath+"/"+handle, deletedPath)
}
