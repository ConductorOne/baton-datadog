package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	Site = field.SelectField(
		"site",
		[]string{
			"datadoghq.com",
			"us3.datadoghq.com",
			"us5.datadoghq.com",
			"datadoghq.eu",
			"ddog-gov.com",
			"ap1.datadoghq.com",
		},
		field.WithDisplayName("Site"),
		field.WithDescription("Part of your Datadog website URL, e.g. datadoghq.com in https://app.datadoghq.com."),
		field.WithRequired(true),
	)
	ApiKey = field.StringField(
		"api-key",
		field.WithDisplayName("API key"),
		field.WithDescription("API key used to authenticate to Datadog API."),
		field.WithRequired(true),
		field.WithIsSecret(true),
	)
	AppKey = field.StringField(
		"app-key",
		field.WithDisplayName("Application key"),
		field.WithDescription("APP key used with API key to assign scopes for API access."),
		field.WithRequired(true),
		field.WithIsSecret(true),
	)
	SyncSecrets = field.BoolField(
		"sync-secrets",
		field.WithDisplayName("Sync secrets"),
		field.WithDescription("Whether to sync secrets or not"),
	)

	// FieldRelationships defines relationships between the fields listed in
	// Config that can be automatically validated. For example, a
	// username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	[]field.SchemaField{
		Site,
		ApiKey,
		AppKey,
		SyncSecrets,
	},
	field.WithConnectorDisplayName("Datadog v2"),
	field.WithHelpUrl("/docs/baton/v1/datadog-v2"),
	field.WithIconUrl("/static/app-icons/datadog.svg"),
)
