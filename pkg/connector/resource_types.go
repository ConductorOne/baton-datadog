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
	// apiTokenResourceType covers organization-scoped API keys (Datadog's
	// "API keys", /api/v2/api_keys): org-wide credentials not owned by any
	// single Datadog identity. This connector still syncs and can delete
	// them, but Issue no longer targets this type -- an org-scoped key
	// issued on behalf of a selected user is not an honest mapping of who
	// holds it. See serviceAccountApplicationKeyResourceType for the type
	// Issue does target. Sync/delete require api_keys_read/api_keys_delete;
	// the DeleteAPIKey endpoint (DELETE /api/v2/api_keys/{api_key_id}) also
	// requires api_keys_write per Datadog's documented permissions, so that
	// is included here so C1 can gate the capability correctly at bind time.
	// CreateAPIKey/FindAPIKeyByName remain on DatadogClient for direct
	// callers and tests.
	apiTokenResourceType = &v2.ResourceType{
		Id:          "api-key",
		DisplayName: "Organization API Key",
		Description: "A Datadog organization API key. Owned by the org, not by any single Datadog identity; not used for credential issuance by this connector.",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions("api_keys_read", "api_keys_write", "api_keys_delete"),
		),
	}
	// serviceAccountApplicationKeyResourceType covers application keys owned
	// by a Datadog service-account user (/api/v2/service_accounts/{id}/application_keys).
	// This is the resource type credential issuance targets: the key is
	// scoped to and owned by one service-account identity, so a synced
	// resource of this type is distinguishable from an apiTokenResourceType
	// (organization API key) by resource type id, display name, and the
	// underlying SecretTrait's credential_detail (see application_key.go).
	serviceAccountApplicationKeyResourceType = &v2.ResourceType{
		Id:          "service-account-application-key",
		DisplayName: "Service Account Application Key",
		Description: "A Datadog application key owned by one service-account identity. Distinct from an org API key (\"api-key\"): scoped to, and deleted through, its owning service account.",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions("user_access_manage"),
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