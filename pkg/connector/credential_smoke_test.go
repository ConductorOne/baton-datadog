package connector

import (
	"context"
	"os"
	"strings"
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

// TestCredentialIssueLifecycle is an opt-in live-provider smoke test. It
// mints a real Datadog service-account application key and always attempts
// to revoke it before returning. Run it only in a disposable Datadog
// organization, against a service account that already exists there:
//
//	DATADOG_CREDENTIAL_SMOKE=1 DATADOG_SMOKE_SITE=datadoghq.com \
//	  DATADOG_SMOKE_API_KEY=... DATADOG_SMOKE_APP_KEY=... \
//	  DATADOG_SMOKE_SERVICE_ACCOUNT_ID=<existing service account user id> \
//	  go test ./pkg/connector -run TestCredentialIssueLifecycle -count=1
func TestCredentialIssueLifecycle(t *testing.T) {
	if os.Getenv("DATADOG_CREDENTIAL_SMOKE") != "1" {
		t.Skip("set DATADOG_CREDENTIAL_SMOKE=1 to run against Datadog")
	}

	site := os.Getenv("DATADOG_SMOKE_SITE")
	apiKey := os.Getenv("DATADOG_SMOKE_API_KEY")
	appKey := os.Getenv("DATADOG_SMOKE_APP_KEY")
	serviceAccountID := os.Getenv("DATADOG_SMOKE_SERVICE_ACCOUNT_ID")
	require.NotEmpty(t, site, "DATADOG_SMOKE_SITE is required")
	require.NotEmpty(t, apiKey, "DATADOG_SMOKE_API_KEY is required")
	require.NotEmpty(t, appKey, "DATADOG_SMOKE_APP_KEY is required")
	require.NotEmpty(t, serviceAccountID, "DATADOG_SMOKE_SERVICE_ACCOUNT_ID is required (issuance targets an existing Datadog service account)")

	ctx := context.Background()
	builder, _, err := New(ctx, &cfg.Datadog{
		Site:        site,
		ApiKey:      apiKey,
		AppKey:      appKey,
		SyncSecrets: true,
	}, nil)
	require.NoError(t, err)
	datadogConnector, ok := builder.(*Datadog)
	require.True(t, ok)

	issuer := newCredentialUserBuilder(datadogConnector.wrapper)
	requestID := "smoke-" + time.Now().UTC().Format("20060102T150405")
	t.Logf("issuing Datadog service account application key with request id %q", requestID)
	issued, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     serviceAccountID,
		},
		RequestID:         requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{ApiKey: v2.CredentialIssueOptions_ApiKey_builder{}.Build()}.Build(),
	})
	require.NoError(t, err)
	revoked := false
	t.Cleanup(func() {
		if revoked || issued == nil || issued.Secret == nil || issued.Secret.GetId() == nil || issued.Secret.GetId().GetResource() == "" {
			return
		}
		secretID := issued.Secret.GetId()
		parentID := issued.Secret.GetParentResourceId()
		_, deleteErr := newApplicationKeyBuilder(datadogConnector.wrapper).Delete(ctx, secretID, parentID)
		if status.Code(deleteErr) != codes.NotFound {
			require.NoError(t, deleteErr, "Datadog application key cleanup failed: %s", secretID.GetResource())
		}
	})
	require.NotNil(t, issued.Secret)
	require.NotEmpty(t, issued.Secret.GetId().GetResource())
	require.Equal(t, serviceAccountID, issued.Secret.GetParentResourceId().GetResource(), "issued secret must record the target service account as its parent resource")
	require.Equal(t, 1, len(issued.PlaintextData))
	require.NotEmpty(t, issued.PlaintextData[0].GetBytes())

	secretID := issued.Secret.GetId()
	appKeyID := secretID.GetResource()
	t.Logf("issued application key id=%s; plaintext material returned but not logged", maskedValue(appKeyID))

	require.True(t, applicationKeyExists(t, ctx, datadogConnector.wrapper, serviceAccountID, appKeyID),
		"issued application key id=%s not found via ListServiceAccountApplicationKeys", maskedValue(appKeyID))
	t.Logf("confirmed application key id=%s exists in Datadog", maskedValue(appKeyID))

	t.Logf("waiting for issued application key id=%s to authenticate", maskedValue(appKeyID))
	require.Eventually(t, func() bool {
		return canAuthenticate(ctx, site, apiKey, string(issued.PlaintextData[0].GetBytes()))
	}, 30*time.Second, time.Second, "issued application key did not become usable")
	t.Logf("confirmed issued application key id=%s can authenticate with Datadog", maskedValue(appKeyID))

	t.Logf("revoking application key id=%s", maskedValue(appKeyID))
	_, err = newApplicationKeyBuilder(datadogConnector.wrapper).Delete(ctx, secretID, issued.Secret.GetParentResourceId())
	require.NoError(t, err, "revoke issued Datadog application key")
	t.Logf("waiting for revoked application key id=%s to stop authenticating", maskedValue(appKeyID))
	require.Eventually(t, func() bool {
		return !canAuthenticate(ctx, site, apiKey, string(issued.PlaintextData[0].GetBytes()))
	}, 30*time.Second, time.Second, "revoked application key can still authenticate with Datadog")
	t.Logf("confirmed revoked application key id=%s can no longer authenticate with Datadog", maskedValue(appKeyID))
	revoked = true

	if applicationKeyExists(t, ctx, datadogConnector.wrapper, serviceAccountID, appKeyID) {
		t.Logf("application key metadata id=%s remains listed after revocation; this does not imply the key can authenticate", maskedValue(appKeyID))
		return
	}
	t.Logf("confirmed application key id=%s is no longer listed for its service account", maskedValue(appKeyID))
}

// applicationKeyExists checks the live provider for appKeyID among
// serviceAccountID's application keys, paging until found or exhausted.
func applicationKeyExists(t *testing.T, ctx context.Context, wrapper *client.DatadogClient, serviceAccountID, appKeyID string) bool {
	t.Helper()
	const maxPages = int64(10_000)
	for page := int64(0); page < maxPages; page++ {
		resp, err := wrapper.ListServiceAccountApplicationKeys(ctx, serviceAccountID, page, defaultV2PageSize)
		require.NoError(t, err)
		keys := resp.GetData()
		for _, key := range keys {
			if key.Id != nil && *key.Id == appKeyID {
				return true
			}
		}
		if int64(len(keys)) < defaultV2PageSize {
			return false
		}
	}
	t.Fatalf("exceeded %d pages listing application keys for service account %q without a short page", maxPages, serviceAccountID)
	return false
}

// canAuthenticate reports whether the given application key, paired with the
// smoke org's API key, can perform an authenticated read. Datadog has no
// application-key-only validation endpoint (unlike /api/v1/validate for API
// keys), so this performs a real authenticated request instead.
func canAuthenticate(ctx context.Context, site, apiKey, applicationKey string) bool {
	cfg := datadog.NewConfiguration()
	official := datadog.NewAPIClient(cfg)
	probe := client.NewDatadogClient(nil, official, site, apiKey, applicationKey)
	_, err := probe.ListTeams(ctx, nil)
	return err == nil
}

func maskedValue(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}
