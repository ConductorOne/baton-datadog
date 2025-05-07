package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	Site = field.StringField(
		"site",
		field.WithDescription("Part of your Datadog website URL, e.g. datadoghq.com in https://app.datadoghq.com."),
		field.WithRequired(true),
	)
	ApiKey = field.StringField(
		"api-key",
		field.WithDescription("API key used to authenticate to Datadog API."),
		field.WithRequired(true),
	)
	AppKey = field.StringField(
		"app-key",
		field.WithDescription("APP key used with API key to assign scopes for API access."),
		field.WithRequired(true),
	)
	SyncSecrets = field.BoolField(
		"sync-secrets",
		field.WithDescription("Whether to sync secrets or not"),
	)

	// FieldRelationships defines relationships between the fields listed in
	// Config that can be automatically validated. For example, a
	// username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

//go:generate go run ./gen
var Config = field.NewConfiguration([]field.SchemaField{
	Site,
	ApiKey,
	AppKey,
	SyncSecrets,
})
