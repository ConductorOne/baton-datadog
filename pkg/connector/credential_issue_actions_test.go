package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	filippoage "filippo.io/age"

	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/conductorone/baton-datadog/local_vendor/baton-multipass-sdk/pkg/multipass"
)

func fullGrantsDatadog(serverURL string) *Datadog {
	return &Datadog{
		wrapper:                           newLifecycleTestWrapper(serverURL),
		baseURL:                           testAPIBaseURL,
		SyncSecrets:                       true,
		AllowOrgAPIKeyDeletion:            true,
		SyncServiceAccountApplicationKeys: true,
	}
}

// registeredIssuerSchemas runs the connector's syncers' ResourceActions into one
// ActionManager and returns the schemas registered for a resource type.
func registeredIssuerSchemas(t *testing.T, d *Datadog, resourceTypeID string) []*v2.BatonActionSchema {
	t.Helper()
	ctx := context.Background()
	mgr := actions.NewActionManager(ctx)
	for _, syncer := range d.ResourceSyncers(ctx) {
		provider, ok := syncer.(connectorbuilder.ResourceActionProvider)
		if !ok {
			continue
		}
		registry, err := mgr.GetTypeRegistry(ctx, syncer.ResourceType(ctx).GetId())
		require.NoError(t, err)
		require.NoError(t, provider.ResourceActions(ctx, registry))
	}
	schemas, _, err := mgr.ListActionSchemas(ctx, resourceTypeID)
	require.NoError(t, err)
	return schemas
}

func fieldsByName(fields []*configv1.Field) map[string]*configv1.Field {
	out := make(map[string]*configv1.Field, len(fields))
	for _, f := range fields {
		out[f.GetName()] = f
	}
	return out
}

// requireIssuerShape asserts what C1 keys on to recognize a credential issuer:
// one RESOURCE_CREATE action, one secret return carrying the Multipass type, and
// one resource return.
func requireIssuerShape(t *testing.T, schema *v2.BatonActionSchema, resourceTypeID, secretName string) {
	t.Helper()
	require.Equal(t, resourceTypeID, schema.GetResourceTypeId())
	require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE}, schema.GetActionType())

	var secrets []*configv1.Field
	var resources []*configv1.Field
	for _, f := range schema.GetReturnTypes() {
		if f.GetIsSecret() {
			secrets = append(secrets, f)
		}
		if f.HasResourceField() {
			resources = append(resources, f)
		}
	}
	require.Len(t, secrets, 1, "exactly one secret return")
	require.Equal(t, secretName, secrets[0].GetName())
	require.Equal(t, multipass.ContentType, secrets[0].GetContentType())
	require.Contains(t, secrets[0].GetTags(), "api_key")
	require.Len(t, resources, 1, "exactly one resource return")
	require.Equal(t, actionReturnResource, resources[0].GetName())
}

func TestOrganizationAPIKeyIssuerSchema(t *testing.T) {
	schemas := registeredIssuerSchemas(t, fullGrantsDatadog("http://127.0.0.1:1"), apiTokenResourceType.Id)
	byName := schemaByName(schemas)
	schema, ok := byName[ActionIssueOrganizationAPIKey]
	require.True(t, ok, "the organization key issuer registers on the api-key type")
	requireIssuerShape(t, schema, apiTokenResourceType.Id, datadogAPIKeyFieldName)

	// An organization key belongs to the organization: no subject, no arguments.
	require.Empty(t, schema.GetArguments())
}

func TestApplicationKeyIssuerSchema(t *testing.T) {
	schemas := registeredIssuerSchemas(t, fullGrantsDatadog("http://127.0.0.1:1"), serviceAccountApplicationKeyResourceType.Id)
	schema, ok := schemaByName(schemas)[ActionIssueServiceAccountApplicationKey]
	require.True(t, ok, "the application key issuer registers on its own type")
	requireIssuerShape(t, schema, serviceAccountApplicationKeyResourceType.Id, datadogApplicationKeyFieldName)

	args := fieldsByName(schema.GetArguments())
	subjects := 0
	for _, a := range schema.GetArguments() {
		if a.HasResourceIdField() {
			subjects++
		}
	}
	require.Equal(t, 1, subjects, "at most one ResourceIdField")
	subject := args[actionArgServiceAccountID]
	require.NotNil(t, subject)
	require.True(t, subject.GetIsRequired())
	require.Equal(t, []string{userResourceType.Id}, subject.GetResourceIdField().GetRules().GetAllowedResourceTypeIds())
	require.True(t, args[actionArgScopes].HasStringSliceField())
}

// TestIssuersFollowTheGrants: an issuer registers only where its secret type's
// revoke path does, the same gates IssueCredential has.
func TestIssuersFollowTheGrants(t *testing.T) {
	d := fullGrantsDatadog("http://127.0.0.1:1")
	d.AllowOrgAPIKeyDeletion = false
	require.Empty(t, registeredIssuerSchemas(t, d, apiTokenResourceType.Id), "no org key issuer without allow-org-api-key-deletion")
	require.NotEmpty(t, registeredIssuerSchemas(t, d, serviceAccountApplicationKeyResourceType.Id))

	d = fullGrantsDatadog("http://127.0.0.1:1")
	d.SyncServiceAccountApplicationKeys = false
	require.Empty(t, registeredIssuerSchemas(t, d, serviceAccountApplicationKeyResourceType.Id))

	d = fullGrantsDatadog("http://127.0.0.1:1")
	d.SyncSecrets = false
	require.Empty(t, registeredIssuerSchemas(t, d, apiTokenResourceType.Id))
	require.Empty(t, registeredIssuerSchemas(t, d, serviceAccountApplicationKeyResourceType.Id))
}

func subjectArg(t *testing.T, resourceType, resource string) *structpb.Value {
	t.Helper()
	v, err := structpb.NewValue(map[string]any{"resource_type_id": resourceType, "resource_id": resource})
	require.NoError(t, err)
	return v
}

// requireResourceReturn checks the returned resource's id and that its
// SecretTrait survived the conversion.
func requireResourceReturn(t *testing.T, response *structpb.Struct, resourceTypeID, resourceID string) {
	t.Helper()
	res := response.GetFields()[actionReturnResource].GetStructValue()
	require.NotNil(t, res, "the response carries the created secret resource")
	id := res.GetFields()["resourceId"].GetStructValue().GetFields()
	require.Equal(t, resourceTypeID, id["resourceTypeId"].GetStringValue())
	require.Equal(t, resourceID, id["resourceId"].GetStringValue())
	require.Contains(t, res.GetFields()["annotations"].String(), "SecretTrait")
}

func TestOrganizationAPIKeyActionResult(t *testing.T) {
	server := newMultipassOrgKeyServer(t)
	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, false, testAPIBaseURL)

	response, plaintext, _, err := u.issueOrganizationAPIKeyAction(context.Background(), &structpb.Struct{})
	require.NoError(t, err)
	requireResourceReturn(t, response, apiTokenResourceType.Id, "org-key-id")
	require.Len(t, plaintext, 1)
	require.Equal(t, datadogAPIKeyFieldName, plaintext[0].GetName())
	require.Equal(t, multipass.ContentType, plaintext[0].GetSchema(), "the SDK does not copy the schema onto the plaintext")
	require.Contains(t, string(plaintext[0].GetBytes()), `"key_value":"org-key-secret"`)
}

func TestApplicationKeyActionResult(t *testing.T) {
	server, requests := newMultipassAppKeyServer(t, "app-key-id", "app-key-secret",
		`{"key":"app-key-secret","name":"c1-tkt-1","scopes":["logs_read"]}`)
	u := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false, true, testAPIBaseURL)

	response, plaintext, _, err := u.issueServiceAccountApplicationKeyAction(context.Background(), &structpb.Struct{Fields: map[string]*structpb.Value{
		actionArgServiceAccountID: subjectArg(t, userResourceType.Id, testServiceAccountID),
		actionArgScopes:           structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("logs_read")}}),
	}})
	require.NoError(t, err)
	requireResourceReturn(t, response, serviceAccountApplicationKeyResourceType.Id, "app-key-id")
	require.Len(t, plaintext, 1)
	require.Equal(t, datadogApplicationKeyFieldName, plaintext[0].GetName())
	require.Equal(t, multipass.ContentType, plaintext[0].GetSchema())
	require.Contains(t, string(plaintext[0].GetBytes()), `"key_value":"app-key-secret"`)

	var created bool
	for _, r := range *requests {
		if r.method == "POST" {
			created = true
			require.Regexp(t, `"name":"c1-\d{8}T\d{6}Z-[a-z2-7]{6}"`, r.body, "the key is named by timestamp and random suffix")
		}
	}
	require.True(t, created)
}

func TestIssuerActionsRejectBadArguments(t *testing.T) {
	u := newCredentialUserBuilder(newLifecycleTestWrapper("http://127.0.0.1:1"), true, true, testAPIBaseURL)
	ctx := context.Background()

	_, _, _, err := u.issueServiceAccountApplicationKeyAction(ctx, &structpb.Struct{Fields: map[string]*structpb.Value{
		actionArgServiceAccountID: subjectArg(t, teamResourceType.Id, "t-1"),
	}})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "the subject must be a user")

	_, _, _, err = u.issueServiceAccountApplicationKeyAction(ctx, &structpb.Struct{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "the subject is required")

	// A malformed scopes list must not be read as absent, which would mint an
	// unscoped key. The wrapper points at a closed port, so reaching Datadog fails
	// with a different code.
	for name, scopes := range map[string]*structpb.Value{
		"string":     structpb.NewStringValue("logs_read"),
		"mixed list": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("x"), structpb.NewNumberValue(5)}}),
		"null":       structpb.NewNullValue(),
	} {
		_, _, _, err = u.issueServiceAccountApplicationKeyAction(ctx, &structpb.Struct{Fields: map[string]*structpb.Value{
			actionArgServiceAccountID: subjectArg(t, userResourceType.Id, testServiceAccountID),
			actionArgScopes:           scopes,
		}})
		require.Equal(t, codes.InvalidArgument, status.Code(err), "scopes as %s must be refused", name)
	}
}

// TestIssuerThroughActionManagerEncryptsTheSecret drives the issuer the way the
// SDK does, with a recipient: the plaintext must leave only as ciphertext whose
// schema is the Multipass type, and the key must not appear in the response.
func TestIssuerThroughActionManagerEncryptsTheSecret(t *testing.T) {
	ctx := context.Background()
	server := newMultipassOrgKeyServer(t)
	d := fullGrantsDatadog(server.URL)

	mgr := actions.NewActionManager(ctx)
	for _, syncer := range d.ResourceSyncers(ctx) {
		if provider, ok := syncer.(connectorbuilder.ResourceActionProvider); ok {
			registry, err := mgr.GetTypeRegistry(ctx, syncer.ResourceType(ctx).GetId())
			require.NoError(t, err)
			require.NoError(t, provider.ResourceActions(ctx, registry))
		}
	}

	identity, err := filippoage.GenerateHybridIdentity()
	require.NoError(t, err)
	recipient := v2.EncryptionConfig_builder{
		AgeRecipientConfig: v2.EncryptionConfig_AgeRecipientConfig_builder{Recipient: identity.Recipient().String()}.Build(),
	}.Build()

	_, actionStatus, response, encrypted, _, err := mgr.InvokeActionWithWaitAndEncryption(
		ctx, ActionIssueOrganizationAPIKey, apiTokenResourceType.Id,
		&structpb.Struct{},
		5*time.Second, []*v2.EncryptionConfig{recipient})
	require.NoError(t, err)
	require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE, actionStatus)

	require.Len(t, encrypted, 1)
	require.Equal(t, datadogAPIKeyFieldName, encrypted[0].GetName())
	require.Equal(t, multipass.ContentType, encrypted[0].GetSchema())
	require.NotContains(t, string(encrypted[0].GetEncryptedBytes()), "org-key-secret")
	require.NotContains(t, response.String(), "org-key-secret", "the public response never carries the key")
	requireResourceReturn(t, response, apiTokenResourceType.Id, "org-key-id")

	reader, err := filippoage.Decrypt(bytes.NewReader(encrypted[0].GetEncryptedBytes()), identity)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Contains(t, string(decrypted), `"key_value":"org-key-secret"`)
}

func TestNewIssuedKeyName(t *testing.T) {
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.FixedZone("x", 3600))
	name, err := newIssuedKeyName(now, bytes.NewReader([]byte{0, 0, 0, 0}))
	require.NoError(t, err)
	require.Equal(t, "c1-20260102T140405Z-aaaaaa", name, "UTC timestamp, base32 suffix")

	again, err := newIssuedKeyName(now, rand.Reader)
	require.NoError(t, err)
	require.Regexp(t, `^c1-\d{8}T\d{6}Z-[a-z2-7]{6}$`, again)

	_, err = newIssuedKeyName(now, bytes.NewReader(nil))
	require.Error(t, err)
}
