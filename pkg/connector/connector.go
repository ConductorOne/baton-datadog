package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type Datadog struct {
	client      *datadog.APIClient
	site        string
	apiKey      string
	appKey      string
	syncSecrets bool
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Datadog) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	resourceSyncers := []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client, d.site, d.apiKey, d.appKey),
		newTeamBuilder(d.client, d.site, d.apiKey, d.appKey),
		newRoleBuilder(d.client, d.site, d.apiKey, d.appKey),
	}

	// Try to create schedule builder, but don't fail if it errors
	if scheduleBuilder, err := newScheduleBuilder(d.client, d.site, d.apiKey, d.appKey); err == nil {
		resourceSyncers = append(resourceSyncers, scheduleBuilder)
	} else {
		// Log the error but continue with other resource syncers
		l := ctxzap.Extract(ctx)
		l.Warn("Failed to create schedule builder, continuing without schedule sync",
			zap.Error(err))
	}

	if d.syncSecrets {
		apiTokenBuilder := newApiTokenBuilder(d.client, d.site, d.apiKey, d.appKey)
		resourceSyncers = append(resourceSyncers, apiTokenBuilder)
	}
	return resourceSyncers
}

// Metadata returns metadata about the connector.
func (d *Datadog) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Baton Datadog Connector",
		Description: "Connector syncing users, teams, and roles from Datadog.",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Datadog) Validate(ctx context.Context) (annotations.Annotations, error) {
	// Validate configuration before making API calls
	if d.site == "" {
		return nil, fmt.Errorf("site cannot be empty")
	}
	if d.apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}
	if d.appKey == "" {
		return nil, fmt.Errorf("application key cannot be empty")
	}

	ctx = withAuthContext(ctx, d.apiKey, d.appKey, d.site)
	api := datadogV1.NewAuthenticationApi(d.client)
	resp, httpRes, err := api.Validate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()

		if !resp.GetValid() {
			return nil, fmt.Errorf("API key not valid with status %d", httpRes.StatusCode)
		}
	} else {
		// If there's no HTTP response, return an error
		return nil, fmt.Errorf("failed to validate API key: no HTTP response received")
	}

	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, site, apiKey, appKey string, syncSecrets bool) (*Datadog, error) {
	// Validate input parameters
	if site == "" {
		return nil, fmt.Errorf("site cannot be empty")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}
	if appKey == "" {
		return nil, fmt.Errorf("application key cannot be empty")
	}

	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	conf := datadog.NewConfiguration()
	conf.HTTPClient = httpClient

	return &Datadog{
		site:        site,
		apiKey:      apiKey,
		appKey:      appKey,
		client:      datadog.NewAPIClient(conf),
		syncSecrets: syncSecrets,
	}, nil
}
