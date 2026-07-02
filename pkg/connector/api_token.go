package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type apiTokenBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
}

var _ connectorbuilder.ResourceSyncer = &apiTokenBuilder{}

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
		if apiToken.Id == nil {
			l := ctxzap.Extract(ctx)
			l.Warn("skipping API token with missing required fields",
				zap.Bool("has_id", apiToken.Id != nil),
			)
			continue
		}

		options := []resource.SecretTraitOption{
			resource.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
			resource.WithSecretDetail("datadog.api_key"),
		}
		if apiToken.Relationships != nil && apiToken.Relationships.CreatedBy != nil {
			userId := apiToken.Relationships.CreatedBy.Data.Id
			options = append(options, resource.WithSecretCreatedByID(&v2.ResourceId{
				ResourceType:  userResourceType.Id,
				Resource:      userId,
				BatonResource: false,
			}))
		}

		timeFormat := time.RFC3339Nano
		if apiToken.Attributes != nil && apiToken.Attributes.CreatedAt != nil {
			createdAt, err := time.Parse(timeFormat, *apiToken.Attributes.CreatedAt)
			if err != nil {
				return nil, "", nil, err
			}
			options = append(options, resource.WithSecretCreatedAt(createdAt))
		}
		if apiToken.Attributes != nil && apiToken.Attributes.ModifiedAt != nil {
			modifiedAt, err := time.Parse(timeFormat, *apiToken.Attributes.ModifiedAt)
			if err != nil {
				return nil, "", nil, err
			}
			options = append(options, resource.WithSecretLastUsedAt(modifiedAt))
		}
		name := *apiToken.Id
		if apiToken.Attributes != nil && apiToken.Attributes.Name != nil {
			name = *apiToken.Attributes.Name
		}
		rv, err := resource.NewSecretResource(
			name,
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
			return nil, "", nil, fmt.Errorf("baton-datadog: failed to get token from page: %w", err)
		}
	}

	return ret, nextPageToken, nil, nil
}

func newApiTokenBuilder(wrapper *client.DatadogClient) *apiTokenBuilder {
	return &apiTokenBuilder{
		resourceType: apiTokenResourceType,
		wrapper:      wrapper,
	}
}
