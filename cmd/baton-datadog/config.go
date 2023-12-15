package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options
	Site           string                   `mapstructure:"site"`
	ApiKey         string                   `mapstructure:"api-key"`
	AppKey         string                   `mapstructure:"app-key"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.Site == "" {
		return fmt.Errorf("site is required, please provide it via --site flag or BATON_SITE environment variable")
	}

	if cfg.ApiKey == "" {
		return fmt.Errorf("API key is required, please provide it via --api-key flag or BATON_API_KEY environment variable")
	}

	if cfg.AppKey == "" {
		return fmt.Errorf("app key is required, please provide it via --app-key flag or BATON_APP_KEY environment variable")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("site", "", "Part of your Datadog website URL, e.g. datadoghq.com in https://app.datadoghq.com. ($BATON_SITE)")
	cmd.PersistentFlags().String("api-key", "", "API key used to authenticate to Datadog API. ($BATON_API_KEY)")
	cmd.PersistentFlags().String("app-key", "", "APP key used with API key to assign scopes for API access. ($BATON_APP_KEY)")
}
