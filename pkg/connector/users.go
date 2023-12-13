package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/helpers"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *datadog.APIClient
	apiKey       string
	appKey       string
	site         string
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return u.resourceType
}

// Create a new connector resource for a Datadog user.
func userResource(user *datadogV2.User) (*v2.Resource, error) {
	firstname, lastname := helpers.SplitFullName(user.Attributes.GetName())
	profile := map[string]interface{}{
		"first_name": firstname,
		"last_name":  lastname,
		"login":      user.Attributes.GetEmail(),
		"user_id":    user.GetId(),
	}

	accountType := v2.UserTrait_ACCOUNT_TYPE_HUMAN
	var status v2.UserTrait_Status_Status
	switch user.Attributes.GetStatus() {
	case "Active":
		status = v2.UserTrait_Status_STATUS_ENABLED
	case "Disabled":
		status = v2.UserTrait_Status_STATUS_DISABLED
	default:
		status = v2.UserTrait_Status_STATUS_UNSPECIFIED
	}

	if user.Attributes.GetServiceAccount() {
		accountType = v2.UserTrait_ACCOUNT_TYPE_SERVICE
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithEmail(user.Attributes.GetEmail(), true),
		rs.WithStatus(status),
		rs.WithAccountType(accountType),
	}

	ret, err := rs.NewUserResource(
		user.Attributes.GetName(),
		userResourceType,
		user.GetId(),
		userTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, u.apiKey, u.appKey, u.site)
	api := datadogV2.NewUsersApi(u.client)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: u.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	users, _, err := api.ListUsers(ctx, *datadogV2.NewListUsersOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error listing users: %w", err)
	}

	var rv []*v2.Resource
	for _, user := range users.GetData() {
		userCopy := user
		ur, err := userResource(&userCopy)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating user resource: %w", err)
		}
		rv = append(rv, ur)
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

// Entitlements always returns an empty slice for users.
func (u *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (u *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *datadog.APIClient, site, apiKey, appKey string) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
