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
	// userResourceType also carries CAPABILITY_CREDENTIAL_ISSUE: when
	// sync-secrets is on, credentialUserBuilder is registered as the user
	// syncer (see connector.go) and Issue mints a service-account
	// application key. That path calls the service-account
	// application-key endpoints, so service_account_write belongs here as
	// well as on serviceAccountApplicationKeyResourceType -- without it C1
	// advertises issuance against a role that gets a 403 from Datadog.
	userResourceType = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions(
				"user_access_invite",
				"user_access_manage",
				"service_account_write",
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
	// Issue does target.
	//
	// The advertised permissions are the ones Datadog's own API spec marks
	// required (the per-operation "x-permission" block) for the only two
	// endpoints the advertised capabilities call: ListAPIKeys, backing
	// CAPABILITY_SYNC, requires api_keys_read, and DeleteAPIKey
	// (DELETE /api/v2/api_keys/{api_key_id}), backing
	// CAPABILITY_RESOURCE_DELETE, requires api_keys_delete. api_keys_delete
	// is a real Datadog permission ("API Keys Delete -- Delete API Keys for
	// your organization", Datadog Admin Role) and is the one that governs
	// delete; api_keys_write is scoped to CreateAPIKey/UpdateAPIKey ("Create
	// and rename API Keys") and is deliberately NOT advertised here, because
	// no advertised capability on this type creates or renames a key.
	// Advertising it would make C1 demand org-wide key-creation rights the
	// connector never exercises. CreateAPIKey/FindAPIKeyByName remain on
	// DatadogClient for tests.
	apiTokenResourceType = &v2.ResourceType{
		Id:          "api-key",
		DisplayName: "Organization API Key",
		Description: "A Datadog organization API key. Owned by the org, not by any single Datadog identity; not used for credential issuance by this connector.",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions("api_keys_read", "api_keys_delete"),
		),
	}
	// serviceAccountApplicationKeyResourceType covers application keys owned
	// by a Datadog service-account user (/api/v2/service_accounts/{id}/application_keys).
	// This is the resource type credential issuance targets: the key is
	// scoped to and owned by one service-account identity, so a synced
	// resource of this type is distinguishable from an apiTokenResourceType
	// (organization API key) by resource type id, display name, and the
	// underlying SecretTrait's credential_detail (see application_key.go).
	//
	// Every service-account application-key endpoint this connector calls is
	// marked service_account_write in Datadog's API spec: the
	// ListServiceAccountApplicationKeys sync path, the
	// CreateServiceAccountApplicationKey issue path, and the
	// DeleteServiceAccountApplicationKey revoke path. Datadog describes that
	// permission as "Create, disable, and use Service Accounts in your
	// organization" (Datadog Admin Role). user_access_manage covers user
	// disable, role management, SAML-to-role mappings and logs restriction
	// queries -- it grants none of the three, so advertising it here would
	// let C1 offer sync/issue/revoke to a role Datadog answers with a 403.
	serviceAccountApplicationKeyResourceType = &v2.ResourceType{
		Id:          "service-account-application-key",
		DisplayName: "Service Account Application Key",
		Description: "A Datadog application key owned by one service-account identity. Distinct from an org API key (\"api-key\"): scoped to, and deleted through, its owning service account.",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions("service_account_write"),
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
