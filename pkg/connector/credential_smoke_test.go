package connector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-datadog/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	t.Logf("issuing Datadog API key with request id %q", requestID)
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
	t.Logf("issued API key id=%s; plaintext material returned but not logged", maskedValue(secretID.GetResource()))
	providerKey, err := datadogConnector.wrapper.GetAPIKey(ctx, secretID.GetResource())
	require.NoError(t, err, "read issued API key from Datadog")
	providerKeyData := providerKey.GetData()
	require.Equal(t, secretID.GetResource(), providerKeyData.GetId())
	t.Logf("confirmed API key id=%s exists in Datadog", maskedValue(secretID.GetResource()))
	issuedKeyValid, err := datadogConnector.wrapper.ValidateAPIKey(ctx, string(issued.PlaintextData[0].GetBytes()))
	require.NoError(t, err, "authenticate with issued API key")
	require.True(t, issuedKeyValid, "issued API key is not accepted by Datadog")
	t.Logf("confirmed issued API key id=%s can authenticate with Datadog", maskedValue(secretID.GetResource()))

	revoked := false
	t.Cleanup(func() {
		if revoked {
			return
		}
		_, deleteErr := newApiTokenBuilder(datadogConnector.wrapper).Delete(ctx, secretID, nil)
		if status.Code(deleteErr) != codes.NotFound {
			require.NoError(t, deleteErr, "Datadog API key cleanup failed: %s", secretID.GetResource())
		}
	})

	t.Logf("revoking API key id=%s", maskedValue(secretID.GetResource()))
	_, err = newApiTokenBuilder(datadogConnector.wrapper).Delete(ctx, secretID, nil)
	require.NoError(t, err, "revoke issued Datadog API key")
	issuedKeyValid, err = datadogConnector.wrapper.ValidateAPIKey(ctx, string(issued.PlaintextData[0].GetBytes()))
	if err != nil {
		require.Contains(t, []codes.Code{codes.Unauthenticated, codes.PermissionDenied}, status.Code(err), "validate revoked API key")
	} else {
		require.False(t, issuedKeyValid, "revoked API key can still authenticate with Datadog")
	}
	t.Logf("confirmed revoked API key id=%s can no longer authenticate with Datadog", maskedValue(secretID.GetResource()))
	revoked = true

	_, err = datadogConnector.wrapper.GetAPIKey(ctx, secretID.GetResource())
	if status.Code(err) == codes.NotFound {
		t.Logf("confirmed API key id=%s is no longer retrievable from Datadog", maskedValue(secretID.GetResource()))
		return
	}
	t.Logf("API key metadata id=%s remains retrievable after revocation; this does not imply the key can authenticate", maskedValue(secretID.GetResource()))
}

func maskedValue(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}
