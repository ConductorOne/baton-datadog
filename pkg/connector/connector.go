package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	cfg "github.com/conductorone/baton-datadog/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

// Compile-time check that Datadog implements the V2 connector interface.
var _ connectorbuilder.ConnectorBuilderV2 = (*Datadog)(nil)

// Compile-time check that Datadog registers global (non-resource-scoped) actions.
var _ connectorbuilder.GlobalActionProvider = (*Datadog)(nil)

type Datadog struct {
	client        *datadog.APIClient
	wrapper       *client.DatadogClient
	site          string
	apiKey        string
	appKey        string
	baseURL       string
	SyncSecrets   bool
	SyncSchedules bool
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Datadog) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	userSyncer := connectorbuilder.ResourceSyncerV2(newUserBuilder(d.wrapper))
	if d.SyncSecrets {
		userSyncer = newCredentialUserBuilder(d.wrapper)
	}
	resourceSyncers := []connectorbuilder.ResourceSyncerV2{
		userSyncer,
		newTeamBuilder(d.wrapper),
		newRoleBuilder(d.wrapper),
	}

	if d.SyncSecrets {
		resourceSyncers = append(resourceSyncers, newApiTokenBuilder(d.wrapper), newApplicationKeyBuilder(d.wrapper))
	}

	if d.SyncSchedules {
		resourceSyncers = append(resourceSyncers, newScheduleBuilder(d.wrapper))
	}

	return resourceSyncers
}

// Metadata returns metadata about the connector.
func (d *Datadog) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Baton Datadog Connector",
		Description: "Connector syncing users, teams, and roles from Datadog.",
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "Email to create the Datadog user with.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Email",
					Order:       1,
				},
				"name": {
					DisplayName: "Full Name",
					Required:    false,
					Description: "Full name to set on the user profile (optional).",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Full Name",
					Order:       2,
				},
				"title": {
					DisplayName: "Title",
					Required:    false,
					Description: "Job title for the user (optional).",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Title",
					Order:       3,
				},
			},
		},
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

// New returns a new instance of the connector. It matches the cli.NewConnector[*cfg.Datadog]
// signature required by config.RunConnector for container/V2 deployment.
func New(ctx context.Context, ddc *cfg.Datadog, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	if err := cfg.ValidateConfig(ddc); err != nil {
		return nil, nil, err
	}

	site := ddc.Site
	apiKey := ddc.ApiKey
	appKey := ddc.AppKey
	baseURL := ddc.BaseUrl
	syncSecrets := ddc.SyncSecrets
	syncSchedules := ddc.SyncSchedules

	// Validate input parameters
	if site == "" {
		return nil, nil, fmt.Errorf("site cannot be empty")
	}
	if apiKey == "" {
		return nil, nil, fmt.Errorf("API key cannot be empty")
	}
	if appKey == "" {
		return nil, nil, fmt.Errorf("application key cannot be empty")
	}

	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	conf := datadog.NewConfiguration()
	conf.HTTPClient = httpClient

	// If baseURL is provided, configure the official client to use it
	if baseURL != "" {
		conf.Servers = datadog.ServerConfigurations{
			{
				URL: baseURL,
			},
		}
	}

	// Create REST client for custom endpoints
	restClient, err := client.NewDatadogRestClient(ctx, site, apiKey, appKey, baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create REST client: %w", err)
	}

	// Create the official client
	officialClient := datadog.NewAPIClient(conf)

	// Create the wrapper client
	wrapper := client.NewDatadogClient(restClient, officialClient, site, apiKey, appKey)

	return &Datadog{
		site:          site,
		apiKey:        apiKey,
		appKey:        appKey,
		baseURL:       baseURL,
		client:        officialClient,
		wrapper:       wrapper,
		SyncSecrets:   syncSecrets,
		SyncSchedules: syncSchedules,
	}, nil, nil
}
