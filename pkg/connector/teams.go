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

const (
	memberRole = "member"
	adminRole  = "admin"
)

type teamBuilder struct {
	resourceType *v2.ResourceType
	client       *datadog.APIClient
	apiKey       string
	appKey       string
	site         string
}

func (t *teamBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return t.resourceType
}

// Create a new connector resource for a Datadog team.
func teamResource(team *datadogV2.Team) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"team_name":        team.Attributes.GetName(),
		"team_description": team.Attributes.GetDescription(),
		"team_id":          team.GetId(),
	}

	teamTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	ret, err := rs.NewGroupResource(
		team.Attributes.GetName(),
		teamResourceType,
		team.GetId(),
		teamTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the teams from the database as resource objects.
func (t *teamBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, t.apiKey, t.appKey, t.site)
	api := datadogV2.NewTeamsApi(t.client)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: t.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	teams, _, err := api.ListTeams(ctx, *datadogV2.NewListTeamsOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error listing teams: %w", err)
	}

	var rv []*v2.Resource
	for _, team := range teams.GetData() {
		teamCopy := team
		tr, err := teamResource(&teamCopy)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating team resource: %w", err)
		}
		rv = append(rv, tr)
	}

	nextPageToken := ""
	if len(teams.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return rv, nextPageToken, nil, nil
}

func (t *teamBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	memberOptions := populateOptions(resource.DisplayName, memberRole)
	memberEntitlement := ent.NewAssignmentEntitlement(resource, memberRole, memberOptions...)

	adminOptions := populateOptions(resource.DisplayName, adminRole)
	adminEntitlement := ent.NewPermissionEntitlement(resource, adminRole, adminOptions...)

	rv = append(rv, memberEntitlement, adminEntitlement)

	return rv, "", nil, nil
}

func (t *teamBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, t.apiKey, t.appKey, t.site)
	teamsApi := datadogV2.NewTeamsApi(t.client)
	usersApi := datadogV2.NewUsersApi(t.client)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: t.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	memberships, _, err := teamsApi.GetTeamMemberships(ctx, resource.Id.Resource, *datadogV2.NewGetTeamMembershipsOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Grant
	for _, membership := range memberships.GetData() {
		userId := membership.Relationships.User.GetData().Id
		res, _, err := usersApi.GetUser(ctx, userId)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error getting user %s from team membership: %w", userId, err)
		}
		user := res.GetData()
		ur, err := userResource(&user)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating user resource for team %s: %w", resource.Id.Resource, err)
		}
		gr := grant.NewGrant(resource, memberRole, ur.Id)
		rv = append(rv, gr)

		if membership.HasAttributes() {
			if membership.Attributes.GetRole() == adminRole {
				gr = grant.NewGrant(resource, adminRole, ur.Id)
				rv = append(rv, gr)
			}
		}
	}

	nextPageToken := ""
	if len(memberships.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return rv, nextPageToken, nil, nil
}

func (t *teamBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-datadog: only users can be granted team membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-datadog: only users can be granted team membership")
	}

	var role *datadogV2.UserTeamRole
	if entitlement.Slug == "admin" {
		role = datadogV2.USERTEAMROLE_ADMIN.Ptr()
	}

	body := datadogV2.UserTeamRequest{
		Data: datadogV2.UserTeamCreate{
			Attributes: &datadogV2.UserTeamAttributes{
				Role: *datadogV2.NewNullableUserTeamRole(role),
			},
			Relationships: &datadogV2.UserTeamRelationships{
				User: &datadogV2.RelationshipToUserTeamUser{
					Data: datadogV2.RelationshipToUserTeamUserData{
						Id:   principal.Id.Resource,
						Type: datadogV2.USERTEAMUSERTYPE_USERS,
					},
				},
			},
			Type: datadogV2.USERTEAMTYPE_TEAM_MEMBERSHIPS,
		},
	}

	ctx = withAuthContext(ctx, t.apiKey, t.appKey, t.site)
	teamsApi := datadogV2.NewTeamsApi(t.client)
	_, _, err := teamsApi.CreateTeamMembership(ctx, entitlement.Resource.Id.Resource, body)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: failed to add user to role: %w", err)
	}

	return nil, nil
}

func (t *teamBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	principal := grant.Principal
	entitlement := grant.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-datadog: only users can have team membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-datadog: only users can have team membership revoked")
	}

	ctx = withAuthContext(ctx, t.apiKey, t.appKey, t.site)
	teamsApi := datadogV2.NewTeamsApi(t.client)

	_, err := teamsApi.DeleteTeamMembership(ctx, entitlement.Resource.Id.Resource, principal.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: failed to remove user from team: %w", err)
	}

	return nil, nil
}

func populateOptions(name, permission string) []ent.EntitlementOption {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s Team %s", name, permission)),
		ent.WithDescription(fmt.Sprintf("%s of %s Datadog team", permission, name)),
	}
	return options
}

func newTeamBuilder(client *datadog.APIClient, site, apiKey, appKey string) *teamBuilder {
	return &teamBuilder{
		resourceType: teamResourceType,
		client:       client,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
