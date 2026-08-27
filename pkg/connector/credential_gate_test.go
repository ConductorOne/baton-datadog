package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
)

// newGateTestConnector builds the connector the way New would, but against a
// fake provider, so a test can read the capabilities C1 would actually be
// advertised for a given flag combination.
func newGateTestConnector(serverURL string, syncSecrets, allowOrgAPIKeyDeletion bool) *Datadog {
	return &Datadog{
		wrapper:                newLifecycleTestWrapper(serverURL),
		site:                   "example.com",
		apiKey:                 "connector-api-key",
		appKey:                 "connector-app-key",
		SyncSecrets:            syncSecrets,
		AllowOrgAPIKeyDeletion: allowOrgAPIKeyDeletion,
	}
}

// resourceTypeCapabilities returns the capabilities the SDK advertises for one
// resource type id, going through NewConnector/GetMetadata rather than
// inspecting the builders directly: the whole point of the gate is what C1
// sees in the advertisement, not what a method exists to do.
func resourceTypeCapabilities(t *testing.T, d *Datadog, resourceTypeID string) []v2.Capability {
	t.Helper()
	ctx := context.Background()
	server, err := connectorbuilder.NewConnector(ctx, d)
	require.NoError(t, err)
	md, err := server.GetMetadata(ctx, &v2.ConnectorServiceGetMetadataRequest{})
	require.NoError(t, err)
	for _, rtc := range md.GetMetadata().GetCapabilities().GetResourceTypeCapabilities() {
		if rtc.GetResourceType().GetId() == resourceTypeID {
			return rtc.GetCapabilities()
		}
	}
	t.Fatalf("resource type %q was not advertised at all", resourceTypeID)
	return nil
}

// TestOrgAPIKeyDeleteRequiresItsOwnGrant is the regression this gate exists
// for: an install already running with sync-secrets on must not acquire
// org-wide Datadog API key deletion by upgrading the connector.
func TestOrgAPIKeyDeleteRequiresItsOwnGrant(t *testing.T) {
	d := newGateTestConnector("http://127.0.0.1:1", true, false)
	caps := resourceTypeCapabilities(t, d, apiTokenResourceType.Id)
	require.Contains(t, caps, v2.Capability_CAPABILITY_SYNC,
		"sync-secrets alone must still sync organization API keys")
	require.NotContains(t, caps, v2.Capability_CAPABILITY_RESOURCE_DELETE,
		"sync-secrets alone must not advertise organization API key deletion")
}

func TestOrgAPIKeyDeleteAdvertisedWithGrant(t *testing.T) {
	d := newGateTestConnector("http://127.0.0.1:1", true, true)
	caps := resourceTypeCapabilities(t, d, apiTokenResourceType.Id)
	require.Contains(t, caps, v2.Capability_CAPABILITY_RESOURCE_DELETE)
}

// TestOrgAPIKeyDeletePermissionFollowsTheGrant checks the advertised Datadog
// permissions track the advertised capabilities: an install that cannot delete
// must not be told to grant api_keys_delete.
func TestOrgAPIKeyDeletePermissionFollowsTheGrant(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name    string
		granted bool
		want    []string
		absent  []string
	}{
		{name: "grant off", granted: false, want: []string{"api_keys_read"}, absent: []string{"api_keys_delete", "api_keys_write"}},
		{name: "grant on", granted: true, want: []string{"api_keys_read", "api_keys_write", "api_keys_delete"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := connectorbuilder.NewConnector(ctx, newGateTestConnector("http://127.0.0.1:1", true, tt.granted))
			require.NoError(t, err)
			md, err := server.GetMetadata(ctx, &v2.ConnectorServiceGetMetadataRequest{})
			require.NoError(t, err)
			var got []string
			for _, rtc := range md.GetMetadata().GetCapabilities().GetResourceTypeCapabilities() {
				if rtc.GetResourceType().GetId() != apiTokenResourceType.Id {
					continue
				}
				for _, p := range rtc.GetPermissions().GetPermissions() {
					got = append(got, p.GetPermission())
				}
			}
			require.ElementsMatch(t, tt.want, got)
			for _, absent := range tt.absent {
				require.NotContains(t, got, absent)
			}
		})
	}
}
