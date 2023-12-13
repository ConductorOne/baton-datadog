package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const roleMembership = "member"

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       *datadog.APIClient
	apiKey       string
	appKey       string
	site         string
}

func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for a Datadog role.
func roleResource(role *datadogV2.Role) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_name": role.Attributes.GetName(),
		"role_id":   role.GetId(),
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	ret, err := rs.NewRoleResource(
		role.Attributes.GetName(),
		roleResourceType,
		role.GetId(),
		roleTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the roles from the database as resource objects.
func (r *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, r.apiKey, r.appKey, r.site)
	api := datadogV2.NewRolesApi(r.client)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: r.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	roles, _, err := api.ListRoles(ctx, *datadogV2.NewListRolesOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, role := range roles.GetData() {
		roleCopy := role
		tr, err := roleResource(&roleCopy)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, tr)
	}

	nextPageToken := ""
	if len(roles.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return rv, nextPageToken, nil, nil
}

func (r *roleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s Role %s", resource.DisplayName, roleMembership)),
		ent.WithDescription(fmt.Sprintf("Member of %s Datadog role", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMembership,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, r.apiKey, r.appKey, r.site)
	rolesApi := datadogV2.NewRolesApi(r.client)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: userResourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	users, _, err := rolesApi.ListRoleUsers(ctx, resource.Id.Resource, *datadogV2.NewListRoleUsersOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error listing users for role %s: %w", resource.DisplayName, err)
	}

	var rv []*v2.Grant
	for _, user := range users.GetData() {
		userCopy := user
		ur, err := userResource(&userCopy)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating user resource for role %s: %w", resource.Id.Resource, err)
		}
		gr := grant.NewGrant(resource, roleMembership, ur.Id)
		rv = append(rv, gr)
	}

	nextPageToken := ""
	if len(users.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return rv, nextPageToken, nil, nil
}

func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-datadog: only users can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-datadog: only users can be granted role membership")
	}

	body := datadogV2.RelationshipToUser{
		Data: datadogV2.RelationshipToUserData{
			Id:   principal.Id.Resource,
			Type: datadogV2.USERSTYPE_USERS,
		},
	}

	ctx = withAuthContext(ctx, r.apiKey, r.appKey, r.site)
	rolesApi := datadogV2.NewRolesApi(r.client)
	_, _, err := rolesApi.AddUserToRole(ctx, entitlement.Resource.Id.Resource, body)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: failed to add user to role: %w", err)
	}

	return nil, nil
}

func (r *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	principal := grant.Principal
	entitlement := grant.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-datadog: only users can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-datadog: only users can have role membership revoked")
	}

	body := datadogV2.RelationshipToUser{
		Data: datadogV2.RelationshipToUserData{
			Id:   principal.Id.Resource,
			Type: datadogV2.USERSTYPE_USERS,
		},
	}

	ctx = withAuthContext(ctx, r.apiKey, r.appKey, r.site)
	rolesApi := datadogV2.NewRolesApi(r.client)
	_, _, err := rolesApi.RemoveUserFromRole(ctx, entitlement.Resource.Id.Resource, body)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: failed to remove user from role: %w", err)
	}

	return nil, nil
}

func newRoleBuilder(client *datadog.APIClient, site, apiKey, appKey string) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       client,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
