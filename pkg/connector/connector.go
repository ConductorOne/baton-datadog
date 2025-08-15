package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

type Datadog struct {
	client      *datadog.APIClient
	wrapper     *client.DatadogClient
	site        string
	apiKey      string
	appKey      string
	syncSecrets bool
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Datadog) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	resourceSyncers := []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.wrapper),
		newTeamBuilder(d.wrapper),
		newRoleBuilder(d.wrapper),
		newScheduleBuilder(d.wrapper),
	}

	if d.syncSecrets {
		resourceSyncers = append(resourceSyncers, newApiTokenBuilder(d.wrapper))
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

	// Use the existing wrapper for validation
	resp, err := d.wrapper.ValidateCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}

	if !resp.GetValid() {
		return nil, fmt.Errorf("API key not valid")
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

	// Create REST client for custom endpoints
	restClient, err := client.NewDatadogRestClient(site, apiKey, appKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create REST client: %w", err)
	}

	// Create the official client
	officialClient := datadog.NewAPIClient(conf)

	// Create the wrapper client
	wrapper := client.NewDatadogClient(restClient, officialClient, site, apiKey, appKey)

	return &Datadog{
		site:        site,
		apiKey:      apiKey,
		appKey:      appKey,
		client:      officialClient,
		wrapper:     wrapper,
		syncSecrets: syncSecrets,
	}, nil
}
