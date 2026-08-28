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
	// AllowOrgAPIKeyDeletion is a destructive grant, deliberately separate from
	// SyncSecrets. Reading organization API keys is not consent to destroy
	// them, and an install that already syncs secrets must not gain org-wide
	// key deletion by upgrading the connector.
	AllowOrgAPIKeyDeletion = field.BoolField(
		"allow-org-api-key-deletion",
		field.WithDescription("Allow this connector to delete Datadog organization API keys. Off by default: syncing secrets does not grant deletion."),
		field.WithDefaultValue(false),
		field.WithDisplayName("Allow organization API key deletion"),
	)
	// SyncServiceAccountApplicationKeys carries the Datadog
	// service_account_write permission, which api_keys_read does not imply.
	// It is off by default because listing a service account's application
	// keys fails the whole sync without that permission: an install already
	// running with sync-secrets on would start failing every sync merely by
	// upgrading the connector. Once granted, the fail-hard behaviour stands --
	// a credential absent from a completed sync reads as deleted.
	SyncServiceAccountApplicationKeys = field.BoolField(
		"sync-service-account-application-keys",
		field.WithDescription("Sync, issue and revoke Datadog service account application keys. Off by default: requires the Datadog service_account_write permission, and a role without it fails the whole sync."),
		field.WithDefaultValue(false),
		field.WithDisplayName("Sync service account application keys"),
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
		field.WithExportTarget(field.ExportTargetCLIOnly),
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
	AllowOrgAPIKeyDeletion,
	SyncServiceAccountApplicationKeys,
	SyncSchedules,
	BaseURL,
},
	field.WithConnectorDisplayName("Datadog"),
	field.WithIconUrl("/static/app-icons/datadog.svg"),
	field.WithHelpUrl("/docs/baton/datadog"),
)

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func ValidateConfig(cfg *Datadog) error {
	return nil
}
