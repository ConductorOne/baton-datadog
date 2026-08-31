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
	// Application-key sync is on for the org-key tests so they read the same
	// connector shape those tests were written against; the tests that gate it
	// build the connector with newAppKeyGateTestConnector instead.
	return newAppKeyGateTestConnector(serverURL, syncSecrets, allowOrgAPIKeyDeletion, true)
}

func newAppKeyGateTestConnector(serverURL string, syncSecrets, allowOrgAPIKeyDeletion, syncServiceAccountApplicationKeys bool) *Datadog {
	// Only the wrapper and the flags matter here: these tests read advertised
	// capabilities, which never touch the connector's own credentials. Leaving
	// them unset keeps credential-shaped literals out of the package.
	return &Datadog{
		wrapper:                           newLifecycleTestWrapper(serverURL),
		site:                              "example.com",
		SyncSecrets:                       syncSecrets,
		AllowOrgAPIKeyDeletion:            allowOrgAPIKeyDeletion,
		SyncServiceAccountApplicationKeys: syncServiceAccountApplicationKeys,
	}
}

// advertisedResourceTypeCapabilities is resourceTypeCapabilities without the
// fatal: a gate whose point is that a resource type is absent needs to ask
// whether it was advertised at all.
func advertisedResourceTypeCapabilities(t *testing.T, d *Datadog, resourceTypeID string) ([]v2.Capability, bool) {
	t.Helper()
	ctx := context.Background()
	server, err := connectorbuilder.NewConnector(ctx, d)
	require.NoError(t, err)
	md, err := server.GetMetadata(ctx, &v2.ConnectorServiceGetMetadataRequest{})
	require.NoError(t, err)
	for _, rtc := range md.GetMetadata().GetCapabilities().GetResourceTypeCapabilities() {
		if rtc.GetResourceType().GetId() == resourceTypeID {
			return rtc.GetCapabilities(), true
		}
	}
	return nil, false
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

// TestApplicationKeySyncRequiresItsOwnGrant is the upgrade regression: listing
// a service account's application keys needs Datadog's service_account_write,
// which api_keys_read does not imply, and a 403 there fails the whole sync.
// An install already running with sync-secrets on must keep syncing after an
// upgrade rather than start failing on a permission it was never asked for.
func TestApplicationKeySyncRequiresItsOwnGrant(t *testing.T) {
	d := newAppKeyGateTestConnector("http://127.0.0.1:1", true, false, false)

	_, advertised := advertisedResourceTypeCapabilities(t, d, serviceAccountApplicationKeyResourceType.Id)
	require.False(t, advertised,
		"sync-secrets alone must not advertise service account application keys")

	orgKeyCaps, advertised := advertisedResourceTypeCapabilities(t, d, apiTokenResourceType.Id)
	require.True(t, advertised, "organization API keys must still sync")
	require.Contains(t, orgKeyCaps, v2.Capability_CAPABILITY_SYNC)
}

func TestApplicationKeySyncAdvertisedWithGrant(t *testing.T) {
	d := newAppKeyGateTestConnector("http://127.0.0.1:1", true, false, true)
	caps, advertised := advertisedResourceTypeCapabilities(t, d, serviceAccountApplicationKeyResourceType.Id)
	require.True(t, advertised)
	require.Contains(t, caps, v2.Capability_CAPABILITY_SYNC)
	require.Contains(t, caps, v2.Capability_CAPABILITY_RESOURCE_DELETE)
}

// TestCredentialIssueFollowsTheKindGrants: with secrets synced but neither
// kind granted there is nothing to issue, so the capability must be absent
// rather than advertised with an empty option list. Either grant brings it
// back.
func TestCredentialIssueFollowsTheKindGrants(t *testing.T) {
	for _, tt := range []struct {
		name      string
		orgKey    bool
		appKey    bool
		wantIssue bool
	}{
		{name: "neither kind granted", wantIssue: false},
		{name: "application keys only", appKey: true, wantIssue: true},
		{name: "organization keys only", orgKey: true, wantIssue: true},
		{name: "both kinds", orgKey: true, appKey: true, wantIssue: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := newAppKeyGateTestConnector("http://127.0.0.1:1", true, tt.orgKey, tt.appKey)
			caps, advertised := advertisedResourceTypeCapabilities(t, d, userResourceType.Id)
			require.True(t, advertised, "users must sync regardless")
			if tt.wantIssue {
				require.Contains(t, caps, v2.Capability_CAPABILITY_CREDENTIAL_ISSUE)
			} else {
				require.NotContains(t, caps, v2.Capability_CAPABILITY_CREDENTIAL_ISSUE)
			}
		})
	}
}
