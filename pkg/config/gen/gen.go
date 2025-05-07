package main

import (
	cfg "github.com/conductorone/baton-datadog/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("datadog", cfg.Config)
}
