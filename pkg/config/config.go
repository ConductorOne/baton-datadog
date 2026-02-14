package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	Site = field.StringField(
		"site",
		field.WithDescription("Part of your Datadog website URL, e.g. datadoghq.com in https://app.datadoghq.com."),
		field.WithRequired(true),
		field.WithDisplayName("Site"),
	)
	ApiKey = field.StringField(
		"api-key",
		field.WithDescription("API key used to authenticate to Datadog API."),
		field.WithRequired(true),
		field.WithIsSecret(true),
		field.WithDisplayName("API key"),
	)
	AppKey = field.StringField(
		"app-key",
		field.WithDescription("APP key used with API key to assign scopes for API access."),
		field.WithRequired(true),
		field.WithIsSecret(true),
		field.WithDisplayName("Application key"),
	)
	SyncSecrets = field.BoolField(
		"sync-secrets",
		field.WithDescription("Whether to sync secrets or not"),
		field.WithDisplayName("Sync secrets"),
	)
	SyncSchedules = field.BoolField(
		"sync-schedules",
		field.WithDescription("Whether to sync on-call schedules or not"),
		field.WithDefaultValue(false),
		field.WithDisplayName("Sync schedules"),
	)
	BaseURL = field.StringField(
		"base-url",
		field.WithDescription("Override the Datadog API URL (for testing)"),
		field.WithDisplayName("Base URL"),
		field.WithHidden(true),
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
	SyncSchedules,
	BaseURL,
})

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func ValidateConfig(cfg *Datadog) error {
	return nil
}
