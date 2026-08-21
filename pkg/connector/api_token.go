package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type apiTokenBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
}

var _ connectorbuilder.ResourceSyncerV2 = &apiTokenBuilder{}
var _ connectorbuilder.ResourceDeleterV2Limited = &apiTokenBuilder{}

func (o *apiTokenBuilder) Delete(ctx context.Context, resourceID *v2.ResourceId, _ *v2.ResourceId) (annotations.Annotations, error) {
	if resourceID == nil {
		return nil, fmt.Errorf("baton-datadog: API key id is required")
	}
	handle := resourceID.GetResource()
	if isMalformedAPIKeyHandle(handle) {
		return nil, fmt.Errorf("baton-datadog: API key id %q is malformed", handle)
	}
	if err := o.wrapper.DeleteAPIKey(ctx, handle); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("baton-datadog: delete API key: %w", err)
	}
	return nil, nil
}

// isMalformedAPIKeyHandle reports whether handle cannot be a valid Datadog API
// key id: empty (including whitespace-only), or containing a control
// character that has no place in an id and is unsafe to embed in a request
// path or log line. The vendored v2 client passes this id through as an
// opaque string with no documented length or charset constraint, so this
// deliberately stays conservative instead of enforcing e.g. UUID shape --
// rejecting a handle Datadog considers valid would break real deletes.
func isMalformedAPIKeyHandle(handle string) bool {
	if strings.TrimSpace(handle) == "" {
		return true
	}
	for _, r := range handle {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (o *apiTokenBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	// API Token secrets do not have entitlements
	return nil, nil, nil
}

func (o *apiTokenBuilder) Grants(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	// API Token secrets do not have grants
	return nil, nil, nil
}

func (o *apiTokenBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *apiTokenBuilder) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	opts resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	res, err := o.wrapper.ListAPIKeys(ctx, datadogV2.NewListAPIKeysOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, nil, fmt.Errorf("error listing api tokens: %w", err)
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

		var resourceOptions []resource.ResourceOption
		timeFormat := time.RFC3339Nano
		if apiToken.Attributes != nil && apiToken.Attributes.CreatedAt != nil {
			createdAt, err := time.Parse(timeFormat, *apiToken.Attributes.CreatedAt)
			if err != nil {
				return nil, nil, err
			}
			resourceOptions = append(resourceOptions, resource.WithResourceCreatedAt(createdAt))
		}
		if apiToken.Attributes != nil && apiToken.Attributes.ModifiedAt != nil {
			modifiedAt, err := time.Parse(timeFormat, *apiToken.Attributes.ModifiedAt)
			if err != nil {
				return nil, nil, err
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
			resourceOptions...,
		)
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, rv)
	}

	nextPageToken := ""
	if len(apiTokens) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-datadog: failed to get token from page: %w", err)
		}
	}

	return ret, &resource.SyncOpResults{NextPageToken: nextPageToken}, nil
}

func newApiTokenBuilder(wrapper *client.DatadogClient) *apiTokenBuilder {
	return &apiTokenBuilder{
		resourceType: apiTokenResourceType,
		wrapper:      wrapper,
	}
}
