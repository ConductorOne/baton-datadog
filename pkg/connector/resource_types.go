package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// Datadog permission names from https://docs.datadoghq.com/account_management/rbac/permissions/
func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

var (
	userResourceType = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions(
				"user_access_invite",
				"user_access_manage",
			),
		),
	}
	roleResourceType = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: annotations.New(
			capabilityPermissions("user_access_manage"),
		),
	}
	teamResourceType = &v2.ResourceType{
		Id:          "team",
		DisplayName: "Team",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: annotations.New(
			capabilityPermissions("user_access_manage"),
		),
	}
	apiTokenResourceType = &v2.ResourceType{
		Id:          "api-key",
		DisplayName: "API Key",
		Description: "Credential issuance creates keys owned by the connector's Datadog principal, not the selected Datadog user.",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions("api_keys_read", "api_keys_write", "api_keys_delete"),
		),
	}
	scheduleResourceType = &v2.ResourceType{
		Id:          "schedule",
		DisplayName: "Schedule",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: annotations.New(
			capabilityPermissions("on_call_read"),
		),
	}
)
