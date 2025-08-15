package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type apiTokenBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
	site         string
	apiKey       string
	appKey       string
}

func (o *apiTokenBuilder) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// API Token secrets do not have entitlements
	return nil, "", nil, nil
}

func (o *apiTokenBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	// API Token secrets do not have grants
	return nil, "", nil, nil
}

func (o *apiTokenBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *apiTokenBuilder) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	pToken *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	ctx = withAuthContext(ctx, o.apiKey, o.appKey, o.site)

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	res, err := o.wrapper.ListAPIKeys(ctx, datadogV2.NewListAPIKeysOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error listing api tokens: %w", err)
	}

	apiTokens := res.GetData()
	ret := make([]*v2.Resource, 0, len(apiTokens))
	for _, apiToken := range apiTokens {
		userId := apiToken.Relationships.CreatedBy.Data.Id
		timeFormat := time.RFC3339Nano
		createdAt, err := time.Parse(timeFormat, *apiToken.Attributes.CreatedAt)
		if err != nil {
			return nil, "", nil, err
		}
		modifiedAt, err := time.Parse(timeFormat, *apiToken.Attributes.ModifiedAt)
		if err != nil {
			return nil, "", nil, err
		}
		options := []resource.SecretTraitOption{
			resource.WithSecretCreatedByID(&v2.ResourceId{
				ResourceType:  userResourceType.Id,
				Resource:      userId,
				BatonResource: false,
			}),
			resource.WithSecretLastUsedAt(modifiedAt),
			resource.WithSecretCreatedAt(createdAt),
		}
		rv, err := resource.NewSecretResource(
			*apiToken.Attributes.Name,
			apiTokenResourceType,
			*apiToken.Id,
			options,
		)
		if err != nil {
			return nil, "", nil, err
		}
		ret = append(ret, rv)
	}

	nextPageToken := ""
	if len(apiTokens) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return ret, nextPageToken, nil, nil
}

func newApiTokenBuilder(wrapper *client.DatadogClient, site, apiKey, appKey string) *apiTokenBuilder {
	return &apiTokenBuilder{
		resourceType: apiTokenResourceType,
		wrapper:      wrapper,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
