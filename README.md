# `baton-datadog` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-datadog.svg)](https://pkg.go.dev/github.com/conductorone/baton-datadog) ![main ci](https://github.com/conductorone/baton-datadog/actions/workflows/main.yaml/badge.svg)

`baton-datadog` is a connector for Datadog built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Datadog API to sync data about users, teams and roles in Datadog organization.
Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## Prerequisites

- Access to the Datadog site.
- API and Application key. To generate an API key go to Organization settings -> API keys -> New Key. To create an Application key go to Organization Settings -> Application Keys -> New Key. 
- You can specify scopes for the Application keys, by default the app key has the same scopes and permissions as the user who created them. For this connector the requred scopes are: 
  - Access Management
  - Teams
- Datadog site. You can identify which site you are on by matching your Datadog website URL to the site URL in the table [here](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site).

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-datadog

BATON_API_KEY=datadogApiKey BATON_APP_KEY=datadogAppKey BATON_SITE=datadogSite baton-datadog
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_API_KEY=datadogApiKey BATON_APP_KEY=datadogAppKey BATON_SITE=datadogSite ghcr.io/conductorone/baton-datadog:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-datadog/cmd/baton-datadog@main

BATON_API_KEY=datadogApiKey BATON_APP_KEY=datadogAppKey BATON_SITE=datadogSite baton-datadog
baton resources
```

# Data Model

`baton-datadog` will pull down information about the following Datadog resources:

- Users
- Roles
- Teams

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-datadog` Command Line Usage

```
baton-datadog

Usage:
  baton-datadog [flags]
  baton-datadog [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --api-key string         API key used to authenticate to Datadog API. ($BATON_API_KEY)
      --app-key string         APP key used with API key to assign scopes for API access. ($BATON_APP_KEY)
      --client-id string       The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string   The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string            The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                   help for baton-datadog
      --log-format string      The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string       The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning           This must be set in order for provisioning actions to be enabled. ($BATON_PROVISIONING)
      --site string            Part of your Datadog website URL, e.g. datadoghq.com in https://app.datadoghq.com. ($BATON_SITE)
  -v, --version                version for baton-datadog

Use "baton-datadog [command] --help" for more information about a command.
```
