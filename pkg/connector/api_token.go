package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type apiTokenBuilder struct {
	resourceType *v2.ResourceType
	client       *datadog.APIClient
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
	l := ctxzap.Extract(ctx)
	ctx = withAuthContext(ctx, o.apiKey, o.appKey, o.site)
	api := datadogV2.NewKeyManagementApi(o.client)
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	res, httpRes, err := api.ListAPIKeys(ctx, *datadogV2.NewListAPIKeysOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error listing api tokens: %w", err)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()
	}

	if httpRes.StatusCode < 200 || httpRes.StatusCode >= 300 {
		l.Info("error listing api tokens", zap.Int("status_code", httpRes.StatusCode))
		return nil, "", nil, fmt.Errorf("error listing api tokens: %s", httpRes.Status)
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
	if len(res.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, "", nil, fmt.Errorf("datadog-connector: failed to get token from page: %w", err)
		}
	}

	return ret, nextPageToken, nil, nil
}

func newApiTokenBuilder(client *datadog.APIClient, site, apiKey, appKey string) *apiTokenBuilder {
	return &apiTokenBuilder{
		resourceType: apiTokenResourceType,
		client:       client,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
