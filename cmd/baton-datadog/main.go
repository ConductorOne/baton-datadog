package main

import (
	"context"

	cfg "github.com/conductorone/baton-datadog/pkg/config"
	"github.com/conductorone/baton-datadog/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var version = "dev"

func main() {
	ctx := context.Background()

	config.RunConnector(
		ctx,
		"baton-datadog",
		version,
		cfg.Config,
		connector.New,
		// Every optional surface is forced on so `./connector capabilities`
		// documents the connector's full capability set. The generated document
		// is static and has no conditional form; the per-install gating lives
		// in ResourceSyncers, keyed on the flags below.
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(&connector.Datadog{
			SyncSecrets:            true,
			SyncSchedules:          true,
			AllowOrgAPIKeyDeletion: true,
		}),
	)
}
