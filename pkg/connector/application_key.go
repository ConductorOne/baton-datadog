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
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type applicationKeyBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
}

var _ connectorbuilder.ResourceSyncerV2 = &applicationKeyBuilder{}
var _ connectorbuilder.ResourceDeleterV2Limited = &applicationKeyBuilder{}

func newApplicationKeyBuilder(wrapper *client.DatadogClient) *applicationKeyBuilder {
	return &applicationKeyBuilder{
		resourceType: serviceAccountApplicationKeyResourceType,
		wrapper:      wrapper,
	}
}

func (o *applicationKeyBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *applicationKeyBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *applicationKeyBuilder) Grants(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

// Delete removes a service-account application key. Datadog's
// DeleteServiceAccountApplicationKey has no delete-by-key-id-alone form: it
// requires both the owning service-account id and the application-key id.
// This connector carries the service-account id through
// ResourceDeleterV2Limited.Delete's parentResourceID parameter -- the SDK's
// own typed slot for exactly this -- rather than packing both ids into a
// single opaque handle string. The handle (resourceID) is still the bare
// provider application-key id, the same shape apiTokenBuilder uses for
// organization API keys.
//
// This is a deliberate design choice, not an accident: no C1 caller today
// constructs a DeleteResourceRequest for credential deletion with either
// parentResourceID populated or a packed composite handle -- both shapes are
// equally unexercised by any real caller as of this writing (verified
// against ductone/c1's source). Choosing parentResourceID keeps the handle
// format generic across credential types (a bare provider id, like every
// other secret this connector syncs) instead of inventing a Datadog-specific
// packing convention, which matters once other connectors need the same
// "delete needs two ids" shape (e.g. GCP service-account keys). The
// ResourceDeleterV2Limited.Delete signature itself is unchanged by this
// choice -- it already took two *v2.ResourceId parameters; apiTokenBuilder
// (organization API keys, which need only one id) simply discards the
// second one. Whatever C1-side caller eventually populates parentResourceID
// for a real delete is a platform-level change this file does not make and
// does not depend on to be correct: until that caller exists, Delete fails
// closed with InvalidArgument rather than guessing.
func (o *applicationKeyBuilder) Delete(ctx context.Context, resourceID *v2.ResourceId, parentResourceID *v2.ResourceId) (annotations.Annotations, error) {
	if resourceID == nil {
		return nil, status.Error(codes.InvalidArgument, "baton-datadog: service account application key id is required")
	}
	appKeyID := resourceID.GetResource()
	if isMalformedAPIKeyHandle(appKeyID) {
		return nil, status.Errorf(codes.InvalidArgument, "baton-datadog: service account application key id %q is malformed", appKeyID)
	}
	if parentResourceID == nil || parentResourceID.GetResourceType() != userResourceType.Id {
		return nil, status.Error(codes.InvalidArgument, "baton-datadog: the owning service account id is required to delete a service account application key")
	}
	serviceAccountID := parentResourceID.GetResource()
	if isMalformedAPIKeyHandle(serviceAccountID) {
		return nil, status.Errorf(codes.InvalidArgument, "baton-datadog: owning service account id %q is malformed", serviceAccountID)
	}
	if err := o.wrapper.DeleteServiceAccountApplicationKey(ctx, serviceAccountID, appKeyID); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("baton-datadog: delete service account application key: %w", err)
	}
	return nil, nil
}

// List syncs every application key owned by a Datadog service account. It
// pages through users (the same page cursor shape apiTokenBuilder/userBuilder
// use), and for each service account found in a page, fully drains that
// service account's own application-key pages via the dedicated
// service-account-scoped list API SPEC-07 requires -- not the org-wide
// application-key list, which would include human-owned keys this
// connector's issuance mapping deliberately never targets.
func (o *applicationKeyBuilder) List(
	ctx context.Context,
	_ *v2.ResourceId,
	opts resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	users, err := o.wrapper.ListUsers(ctx, datadogV2.NewListUsersOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: list users while syncing service account application keys: %w", err)
	}

	var ret []*v2.Resource
	for _, user := range users.GetData() {
		if user.Attributes == nil || !user.Attributes.GetServiceAccount() {
			continue
		}
		serviceAccountID := user.GetId()
		if serviceAccountID == "" {
			continue
		}
		serviceAccountResourceID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: serviceAccountID}

		for appKeyPage := int64(0); ; appKeyPage++ {
			resp, err := o.wrapper.ListServiceAccountApplicationKeys(ctx, serviceAccountID, appKeyPage, defaultV2PageSize)
			if err != nil {
				return nil, nil, fmt.Errorf("baton-datadog: list application keys for service account %q: %w", serviceAccountID, err)
			}
			keys := resp.GetData()
			for _, key := range keys {
				if key.Id == nil {
					continue
				}
				rv, err := applicationKeyResource(*key.Id, serviceAccountResourceID, key.Attributes)
				if err != nil {
					return nil, nil, err
				}
				ret = append(ret, rv)
			}
			if int64(len(keys)) < defaultV2PageSize {
				break
			}
		}
	}

	nextPageToken := ""
	if len(users.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-datadog: failed to get token from page: %w", err)
		}
	}

	return ret, &resource.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// applicationKeyResource builds the synced resource for one service-account
// application key. The type is unambiguous through two structured signals a
// reader (or a future requester-selection surface) can consume without
// inferring anything from prose: the resource type id/display name
// (serviceAccountApplicationKeyResourceType, distinct from apiTokenResourceType),
// and SecretTrait.credential_detail ("datadog.service_account_application_key",
// set via WithSecretDetail below) -- a structured field on the trait, not
// display-name text. WithParentResourceID records the owning service account
// as the resource's parent; see Delete's doc comment for why that is the
// field this connector's delete path relies on.
func applicationKeyResource(appKeyID string, serviceAccountResourceID *v2.ResourceId, attrs *datadogV2.PartialApplicationKeyAttributes) (*v2.Resource, error) {
	name := appKeyID
	if attrs != nil && attrs.Name != nil {
		name = *attrs.Name
	}

	options := []resource.SecretTraitOption{
		resource.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		resource.WithSecretDetail("datadog.service_account_application_key"),
		resource.WithSecretCreatedByID(serviceAccountResourceID),
		resource.WithSecretIdentityID(serviceAccountResourceID),
	}

	resourceOptions := []resource.ResourceOption{
		resource.WithParentResourceID(serviceAccountResourceID),
	}
	if attrs != nil && attrs.CreatedAt != nil {
		createdAt, err := time.Parse(time.RFC3339Nano, *attrs.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("baton-datadog: parse application key created_at: %w", err)
		}
		resourceOptions = append(resourceOptions, resource.WithResourceCreatedAt(createdAt))
	}

	return resource.NewSecretResource(
		name,
		serviceAccountApplicationKeyResourceType,
		appKeyID,
		options,
		resourceOptions...,
	)
}
