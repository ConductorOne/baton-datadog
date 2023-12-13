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
)

type Datadog struct {
	client *datadog.APIClient
	site   string
	apiKey string
	appKey string
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Datadog) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client, d.site, d.apiKey, d.appKey),
		newTeamBuilder(d.client, d.site, d.apiKey, d.appKey),
		newRoleBuilder(d.client, d.site, d.apiKey, d.appKey),
	}
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
	ctx = withAuthContext(ctx, d.apiKey, d.appKey, d.site)
	api := datadogV1.NewAuthenticationApi(d.client)
	resp, _, err := api.Validate(ctx)
	if err != nil {
		return nil, fmt.Errorf("datadog-connector: failed to validate API key: %w", err)
	}

	if !resp.GetValid() {
		return nil, fmt.Errorf("datadog-connector: API key not valid")
	}

	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, site, apiKey, appKey string) (*Datadog, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	conf := datadog.NewConfiguration()
	conf.HTTPClient = httpClient

	return &Datadog{
		site:   site,
		apiKey: apiKey,
		appKey: appKey,
		client: datadog.NewAPIClient(conf),
	}, nil
}
