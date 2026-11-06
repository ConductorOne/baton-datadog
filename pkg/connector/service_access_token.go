package connector

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The handle carries both immutable provider IDs because the SDK's current
// delete caller does not reliably supply parentResourceID. The token's bare
// provider ID stays in the native key_id field.
func serviceAccessTokenHandle(serviceAccountID, tokenID string) string {
	return "sat:" + base64.RawURLEncoding.EncodeToString([]byte(serviceAccountID+"\x00"+tokenID))
}

func parseServiceAccessTokenHandle(handle string) (string, string, error) {
	if !strings.HasPrefix(handle, "sat:") {
		return "", "", status.Error(codes.InvalidArgument, "baton-datadog: malformed service access token handle")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(handle, "sat:"))
	if err != nil {
		return "", "", status.Error(codes.InvalidArgument, "baton-datadog: malformed service access token handle")
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 2 || isMalformedAPIKeyHandle(parts[0]) || isMalformedAPIKeyHandle(parts[1]) {
		return "", "", status.Error(codes.InvalidArgument, "baton-datadog: malformed service access token handle")
	}
	return parts[0], parts[1], nil
}

type serviceAccessTokenBuilder struct {
	wrapper *client.DatadogClient
}

var _ connectorbuilder.ResourceSyncerV2 = &serviceAccessTokenBuilder{}
var _ connectorbuilder.ResourceDeleterV2Limited = &serviceAccessTokenBuilder{}

func newServiceAccessTokenBuilder(wrapper *client.DatadogClient) *serviceAccessTokenBuilder {
	return &serviceAccessTokenBuilder{wrapper: wrapper}
}

func (o *serviceAccessTokenBuilder) ResourceType(context.Context) *v2.ResourceType {
	return serviceAccountAccessTokenResourceType
}

func (o *serviceAccessTokenBuilder) Entitlements(context.Context, *v2.Resource, resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *serviceAccessTokenBuilder) Grants(context.Context, *v2.Resource, resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *serviceAccessTokenBuilder) Delete(ctx context.Context, id, _ *v2.ResourceId) (annotations.Annotations, error) {
	if id == nil {
		return nil, status.Error(codes.InvalidArgument, "baton-datadog: service access token handle is required")
	}
	serviceAccountID, tokenID, err := parseServiceAccessTokenHandle(id.GetResource())
	if err != nil {
		return nil, err
	}
	if err := o.wrapper.RevokeServiceAccountAccessToken(ctx, serviceAccountID, tokenID); err != nil && status.Code(err) != codes.NotFound {
		return nil, fmt.Errorf("baton-datadog: revoke service access token: %w", err)
	}
	return nil, nil
}

func (o *serviceAccessTokenBuilder) List(ctx context.Context, _ *v2.ResourceId, opts resource.SyncOpAttrs) ([]*v2.Resource, *resource.SyncOpResults, error) {
	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: serviceAccountAccessTokenResourceType.Id})
	if err != nil {
		return nil, nil, err
	}
	if current := bag.Current(); current != nil && current.ResourceTypeID == userResourceType.Id && current.ResourceID != "" {
		return o.listTokenPage(ctx, bag, current.ResourceID, page)
	}
	return o.listUsersPage(ctx, bag, page)
}

func (o *serviceAccessTokenBuilder) listUsersPage(ctx context.Context, bag *pagination.Bag, page int64) ([]*v2.Resource, *resource.SyncOpResults, error) {
	if page >= maxUserPages {
		return nil, nil, fmt.Errorf("baton-datadog: exceeded %d user pages while syncing service access tokens", maxUserPages)
	}
	users, err := o.wrapper.ListUsers(ctx, datadogV2.NewListUsersOptionalParameters().WithPageNumber(page).WithPageSize(defaultV2PageSize))
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: list service accounts for access tokens: %w", err)
	}
	data := users.GetData()
	if len(data) == 0 {
		bag.Pop()
	} else if err := bag.Next(strconv.FormatInt(page+1, 10)); err != nil {
		return nil, nil, err
	}
	for _, user := range data {
		if user.Attributes == nil || !user.Attributes.GetServiceAccount() || user.Attributes.GetDisabled() || user.GetId() == "" {
			continue
		}
		bag.Push(pagination.PageState{ResourceTypeID: userResourceType.Id, ResourceID: user.GetId()})
	}
	next, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return nil, &resource.SyncOpResults{NextPageToken: next}, nil
}

func (o *serviceAccessTokenBuilder) listTokenPage(ctx context.Context, bag *pagination.Bag, serviceAccountID string, page int64) ([]*v2.Resource, *resource.SyncOpResults, error) {
	if page >= maxApplicationKeyPages {
		return nil, nil, fmt.Errorf("baton-datadog: exceeded %d service access token pages for %q", maxApplicationKeyPages, serviceAccountID)
	}
	tokens, err := o.wrapper.ListServiceAccountAccessTokens(ctx, serviceAccountID, page, defaultV2PageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: list access tokens for service account %q: %w", serviceAccountID, err)
	}
	ret := make([]*v2.Resource, 0, len(tokens))
	for _, token := range tokens {
		secret, err := serviceAccessTokenResource(serviceAccountID, &token)
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, secret)
	}
	if int64(len(tokens)) < defaultV2PageSize {
		bag.Pop()
	} else if err := bag.Next(strconv.FormatInt(page+1, 10)); err != nil {
		return nil, nil, err
	}
	next, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return ret, &resource.SyncOpResults{NextPageToken: next}, nil
}

func serviceAccessTokenResource(serviceAccountID string, token *client.ServiceAccessToken) (*v2.Resource, error) {
	owner := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: serviceAccountID}
	name := token.ID
	trait := []resource.SecretTraitOption{
		resource.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		resource.WithSecretDetail("datadog.service_access_token"),
		resource.WithSecretIdentityID(owner),
	}
	options := []resource.ResourceOption{resource.WithParentResourceID(owner)}
	if token.Name != "" {
		name = token.Name
	}
	if token.ExpiresAt != nil {
		trait = append(trait, resource.WithSecretExpiresAt(*token.ExpiresAt))
	}
	if token.LastUsedAt != nil {
		trait = append(trait, resource.WithSecretLastUsedAt(*token.LastUsedAt))
	}
	if token.CreatedAt != nil {
		options = append(options, resource.WithResourceCreatedAt(*token.CreatedAt))
	}
	if token.Scopes != nil {
		options = append(options, applicationKeyProfileOptions(&token.Scopes)...)
	}
	return resource.NewSecretResource(name, serviceAccountAccessTokenResourceType, serviceAccessTokenHandle(serviceAccountID, token.ID), trait, options...)
}
