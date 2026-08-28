package connector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	cfg "github.com/conductorone/baton-datadog/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestOrganizationAPIKeyIssueLifecycle is the opt-in live-provider smoke test
// for the second issuance kind. It mints a real Datadog ORGANIZATION API key,
// which is org-wide and unscoped, and always attempts to revoke it before
// returning. Run it only in a disposable Datadog organization:
//
//	DATADOG_CREDENTIAL_SMOKE=1 DATADOG_SMOKE_SITE=datadoghq.com \
//	  DATADOG_SMOKE_API_KEY=... DATADOG_SMOKE_APP_KEY=... \
//	  DATADOG_SMOKE_SERVICE_ACCOUNT_ID=<any existing service account user id> \
//	  go test ./pkg/connector -run TestOrganizationAPIKeyIssueLifecycle -count=1
//
// The service account id is only the identity the key is recorded as vended
// to. Unlike an application key, an organization API key has no provider-side
// owner, so Datadog never associates the key with that user.
func TestOrganizationAPIKeyIssueLifecycle(t *testing.T) {
	if os.Getenv("DATADOG_CREDENTIAL_SMOKE") != "1" {
		t.Skip("set DATADOG_CREDENTIAL_SMOKE=1 to run against Datadog")
	}

	site := os.Getenv("DATADOG_SMOKE_SITE")
	apiKey := os.Getenv("DATADOG_SMOKE_API_KEY")
	appKey := os.Getenv("DATADOG_SMOKE_APP_KEY")
	identityID := os.Getenv("DATADOG_SMOKE_SERVICE_ACCOUNT_ID")
	require.NotEmpty(t, site, "DATADOG_SMOKE_SITE is required")
	require.NotEmpty(t, apiKey, "DATADOG_SMOKE_API_KEY is required")
	require.NotEmpty(t, appKey, "DATADOG_SMOKE_APP_KEY is required")
	require.NotEmpty(t, identityID, "DATADOG_SMOKE_SERVICE_ACCOUNT_ID is required as the identity the key is vended to")

	ctx := context.Background()
	builder, _, err := New(ctx, &cfg.Datadog{
		Site:                   site,
		ApiKey:                 apiKey,
		AppKey:                 appKey,
		SyncSecrets:            true,
		AllowOrgApiKeyDeletion: true,
	}, nil)
	require.NoError(t, err)
	datadogConnector, ok := builder.(*Datadog)
	require.True(t, ok)

	// The grant is what puts the organization API key on the menu at all.
	details, _, err := newCredentialUserBuilder(datadogConnector.wrapper, datadogConnector.AllowOrgAPIKeyDeletion).IssueCapabilityDetails(ctx)
	require.NoError(t, err)
	var advertised bool
	for _, descriptor := range details.GetOptions() {
		if descriptor.GetSecretResourceTypeId() == apiTokenResourceType.Id {
			advertised = true
		}
	}
	require.True(t, advertised, "organization API key issuance must be advertised when the grant is set")

	issuer := newCredentialUserBuilder(datadogConnector.wrapper, true)
	requestID := "orgsmoke-" + time.Now().UTC().Format("20060102T150405")
	t.Logf("issuing Datadog organization API key with request id %q", requestID)
	issued, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: identityID},
		RequestID:  requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: apiTokenResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
	})
	require.NoError(t, err)
	revoked := false
	t.Cleanup(func() {
		if revoked || issued == nil || issued.Secret == nil || issued.Secret.GetId().GetResource() == "" {
			return
		}
		_, deleteErr := newDeletableAPITokenBuilder(datadogConnector.wrapper).Delete(ctx, issued.Secret.GetId(), nil)
		if status.Code(deleteErr) != codes.NotFound {
			require.NoError(t, deleteErr, "Datadog organization API key cleanup failed: %s", issued.Secret.GetId().GetResource())
		}
	})

	require.NotNil(t, issued.Secret)
	require.Equal(t, apiTokenResourceType.Id, issued.Secret.GetId().GetResourceType(),
		"the issued resource must come back as the kind that was requested, not the preferred one")
	require.Nil(t, issued.Secret.GetParentResourceId(),
		"an organization API key belongs to the organization, not to the identity it was vended to")
	require.Len(t, issued.PlaintextData, 1)
	require.Equal(t, "api_key", issued.PlaintextData[0].GetName())
	require.NotEmpty(t, issued.PlaintextData[0].GetBytes())

	orgKeyID := issued.Secret.GetId().GetResource()
	t.Logf("issued organization API key id=%s; plaintext material returned but not logged", maskedValue(orgKeyID))

	found, err := datadogConnector.wrapper.FindAPIKeyByName(ctx, "c1-"+requestID)
	require.NoError(t, err)
	require.NotNil(t, found, "issued organization API key id=%s not found via ListAPIKeys", maskedValue(orgKeyID))
	t.Logf("confirmed organization API key id=%s exists in Datadog", maskedValue(orgKeyID))

	issuedKey := string(issued.PlaintextData[0].GetBytes())
	t.Logf("waiting for issued organization API key id=%s to authenticate", maskedValue(orgKeyID))
	require.Eventually(t, func() bool {
		ok, err := orgAPIKeyValidates(ctx, site, issuedKey)
		if err != nil {
			t.Logf("issued organization API key not usable yet: %v", err)
			return false
		}
		return ok
	}, 30*time.Second, time.Second, "issued organization API key did not become usable")
	t.Logf("confirmed issued organization API key id=%s authenticates with Datadog", maskedValue(orgKeyID))

	t.Logf("revoking organization API key id=%s", maskedValue(orgKeyID))
	_, err = newDeletableAPITokenBuilder(datadogConnector.wrapper).Delete(ctx, issued.Secret.GetId(), nil)
	require.NoError(t, err, "revoke issued Datadog organization API key")
	t.Logf("waiting for revoked organization API key id=%s to stop authenticating", maskedValue(orgKeyID))
	require.Eventually(t, func() bool {
		ok, err := orgAPIKeyValidates(ctx, site, issuedKey)
		if err != nil {
			t.Logf("revocation probe failed without an answer; retrying: %v", err)
			return false
		}
		return !ok
	}, 30*time.Second, time.Second, "revoked organization API key still authenticates with Datadog")
	t.Logf("confirmed revoked organization API key id=%s no longer authenticates", maskedValue(orgKeyID))
	revoked = true

	found, err = datadogConnector.wrapper.FindAPIKeyByName(ctx, "c1-"+requestID)
	require.NoError(t, err)
	require.Nil(t, found, "revoked organization API key id=%s is still listed", maskedValue(orgKeyID))
	t.Logf("confirmed organization API key id=%s is no longer listed", maskedValue(orgKeyID))
}

// orgAPIKeyValidates asks Datadog whether one organization API key is live.
// It goes through the connector's own client rather than a hand-rolled request:
// GET /api/v1/validate authenticates on the API key alone, which is what makes
// it the right probe here. An organization API key has no application key to
// pair with, so a probe that required one would not isolate the credential
// under test. The empty application key is deliberate.
func orgAPIKeyValidates(ctx context.Context, site, apiKey string) (bool, error) {
	cfg := datadog.NewConfiguration()
	probe := client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), site, apiKey, "")
	resp, err := probe.ValidateCredentials(ctx)
	if err != nil {
		// Datadog refusing the credential is the answer, not a probe failure.
		if isCredentialRejection(err) {
			return false, nil
		}
		return false, err
	}
	return resp.GetValid(), nil
}
