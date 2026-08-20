package connector

import (
	"context"
	"os"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-datadog/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
)

// TestCredentialIssueLifecycle is an opt-in live-provider smoke test. It creates
// a real Datadog API key and always attempts to revoke it before returning.
// Run it only in a disposable Datadog organization:
//
// DATADOG_CREDENTIAL_SMOKE=1 BATON_SITE=datadoghq.com BATON_API_KEY=... BATON_APP_KEY=... \
//   go test ./pkg/connector -run TestCredentialIssueLifecycle -count=1
func TestCredentialIssueLifecycle(t *testing.T) {
	if os.Getenv("DATADOG_CREDENTIAL_SMOKE") != "1" {
		t.Skip("set DATADOG_CREDENTIAL_SMOKE=1 to run against Datadog")
	}

	site := os.Getenv("BATON_SITE")
	apiKey := os.Getenv("BATON_API_KEY")
	appKey := os.Getenv("BATON_APP_KEY")
	require.NotEmpty(t, site, "BATON_SITE is required")
	require.NotEmpty(t, apiKey, "BATON_API_KEY is required")
	require.NotEmpty(t, appKey, "BATON_APP_KEY is required")

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
	issued, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     "credential-smoke-test",
		},
		RequestID: requestID,
	})
	require.NoError(t, err)
	require.NotNil(t, issued.Secret)
	require.NotEmpty(t, issued.Secret.GetId().GetResource())
	require.Len(t, issued.PlaintextData, 1)
	require.NotEmpty(t, issued.PlaintextData[0].GetBytes())

	secretID := issued.Secret.GetId()
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		_, deleteErr := newApiTokenBuilder(datadogConnector.wrapper).Delete(ctx, secretID, nil)
		require.NoError(t, deleteErr, "Datadog API key cleanup failed: %s", secretID.GetResource())
	})

	_, err = newApiTokenBuilder(datadogConnector.wrapper).Delete(ctx, secretID, nil)
	require.NoError(t, err, "revoke issued Datadog API key")
	deleted = true

	keys, err := datadogConnector.wrapper.ListAPIKeys(ctx, nil)
	require.NoError(t, err, "list API keys after revocation")
	for _, key := range keys.GetData() {
		require.NotEqual(t, secretID.GetResource(), key.GetId(), "revoked API key is still listed")
	}
}
