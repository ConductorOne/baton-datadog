package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"
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

	ConfigurationFields = []field.SchemaField{
		Site,
		ApiKey,
		AppKey,
		SyncSecrets,
	}

	// FieldRelationships defines relationships between the fields listed in
	// ConfigurationFields that can be automatically validated. For example, a
	// username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func ValidateConfig(v *viper.Viper) error {
	return nil
}
