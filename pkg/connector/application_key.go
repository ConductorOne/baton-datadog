package connector

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type applicationKeyBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient

	// skippedServiceAccounts counts how many service accounts the current walk
	// has skipped because their application keys could not be read. The warning
	// that reports a skip is sampled (L7): the case it exists for is a role
	// missing service_account_write org-wide, which makes it fire for every
	// service account. It is reset at the start of each walk (see List) because
	// this builder outlives any single sync.
	skippedServiceAccounts atomic.Int64
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

// maxApplicationKeyPages bounds one service account's application-key paging
// so a provider that ignores page[number] and keeps returning full pages
// fails closed instead of paging forever. 10_000 pages (1M keys) is far
// beyond any real service account's application-key count.
const maxApplicationKeyPages = int64(10_000)

// List returns at most one provider page per call. The sync walks two levels:
// the users pages, to discover which users are service accounts, and then each
// service account's own application-key pages, read through the dedicated
// service-account-scoped list API SPEC-07 requires -- not the org-wide
// application-key list, which would include human-owned keys this connector's
// issuance mapping deliberately never targets.
//
// Both levels live in the pagination bag: a users-level state at the bottom,
// and one child state per discovered service account pushed above it. Because
// the bag is a stack, a users page's service accounts are fully drained before
// the next users page is fetched, and every call issues exactly one provider
// list request. Draining every application-key page for every service account
// inside a single List call is the F2 pattern the connector criteria forbid --
// it denies the SDK any chance to checkpoint, respect rate limits, or cancel,
// and buffers the whole org's keys in memory first.
func (o *applicationKeyBuilder) List(
	ctx context.Context,
	_ *v2.ResourceId,
	opts resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	// An empty page token is the first call of a walk, so the skip-warning
	// sampling counter restarts here and each sync gets its own 1/10/100
	// schedule. The builder is constructed once per connector process --
	// Datadog.ResourceSyncers runs inside connectorbuilder.NewConnector, whose
	// result is reused for every sync -- so without this reset the first sync
	// consumes the early log slots and a later sync against the same org-wide
	// missing permission would emit nothing until the running total reached
	// 1000.
	//
	// An empty token is a safe first-walk signal for this builder: List only
	// ever returns an empty NextPageToken from bag.Marshal() with an empty
	// bag, and the bag can only be emptied by popping the users-level state,
	// which happens solely on an empty users page -- the end of the walk. So
	// no mid-walk call can carry one. (parsePageToken also accepts a "page:N"
	// seed form, which nothing produces for this resource type; if one ever
	// did, the counter would merely carry over rather than misbehave.) A
	// retried first page resets again, which is what a restarted walk wants.
	if opts.PageToken.Token == "" {
		o.skippedServiceAccounts.Store(0)
	}

	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: o.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	// A child state names the service account whose application keys it is
	// paging; the users-level state carries no resource id.
	if current := bag.Current(); current != nil &&
		current.ResourceTypeID == userResourceType.Id && current.ResourceID != "" {
		return o.listApplicationKeyPage(ctx, bag, current.ResourceID, page)
	}
	return o.listServiceAccountsPage(ctx, bag, page)
}

// listServiceAccountsPage consumes one users page and pushes a child state for
// every service account on it. It returns no resources of its own -- the
// application keys are produced by those child states on subsequent calls.
func (o *applicationKeyBuilder) listServiceAccountsPage(
	ctx context.Context,
	bag *pagination.Bag,
	page int64,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	users, err := o.wrapper.ListUsers(ctx, datadogV2.NewListUsersOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: list users while syncing service account application keys: %w", err)
	}

	data := users.GetData()
	if len(data) == 0 {
		// Users are exhausted: drop the users-level state so the sync ends
		// once the child states pushed by earlier pages are drained.
		bag.Pop()
	} else if err := bag.Next(strconv.FormatInt(page+1, 10)); err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: advance users page: %w", err)
	}

	for _, user := range data {
		if user.Attributes == nil || !user.Attributes.GetServiceAccount() {
			continue
		}
		serviceAccountID := user.GetId()
		if serviceAccountID == "" {
			continue
		}
		bag.Push(pagination.PageState{
			ResourceTypeID: userResourceType.Id,
			ResourceID:     serviceAccountID,
		})
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: marshal pagination bag: %w", err)
	}
	return nil, &resource.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// listApplicationKeyPage returns one page of a single service account's
// application keys.
func (o *applicationKeyBuilder) listApplicationKeyPage(
	ctx context.Context,
	bag *pagination.Bag,
	serviceAccountID string,
	page int64,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	if page >= maxApplicationKeyPages {
		return nil, nil, fmt.Errorf(
			"baton-datadog: exceeded %d application-key pages for service account %q without a short page",
			maxApplicationKeyPages, serviceAccountID)
	}

	resp, err := o.wrapper.ListServiceAccountApplicationKeys(ctx, serviceAccountID, page, defaultV2PageSize)
	if err != nil {
		// ListServiceAccountApplicationKeys requires Datadog's
		// service_account_write permission, which this sync path is the
		// first to need: an install that already had sync-secrets on for
		// read-only key inventory may run a read-mostly custom role that
		// lacks it. A service account can also be deleted mid-sync. Warn and
		// skip that one service account rather than failing the whole sync
		// (criteria R7); every other provider error still fails hard.
		if code := status.Code(err); code == codes.PermissionDenied || code == codes.NotFound {
			// Sampled, not per-service-account: an org-wide missing
			// service_account_write would otherwise emit one line per service
			// account on every sync. total_occurrences keeps the real count
			// visible on the lines that do get through.
			if total := o.skippedServiceAccounts.Add(1); shouldLogSampled(total) {
				ctxzap.Extract(ctx).Warn(
					"baton-datadog: skipping application keys for service account",
					zap.String("service_account_id", serviceAccountID),
					zap.String("code", code.String()),
					zap.Int64("total_occurrences", total),
					zap.Error(err),
				)
			}
			bag.Pop()
			nextPageToken, marshalErr := bag.Marshal()
			if marshalErr != nil {
				return nil, nil, fmt.Errorf("baton-datadog: marshal pagination bag: %w", marshalErr)
			}
			return nil, &resource.SyncOpResults{NextPageToken: nextPageToken}, nil
		}
		return nil, nil, fmt.Errorf("baton-datadog: list application keys for service account %q: %w", serviceAccountID, err)
	}

	serviceAccountResourceID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: serviceAccountID}
	keys := resp.GetData()
	ret := make([]*v2.Resource, 0, len(keys))
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
		// Short page: this service account is done.
		bag.Pop()
	} else if err := bag.Next(strconv.FormatInt(page+1, 10)); err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: advance application-key page: %w", err)
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: marshal pagination bag: %w", err)
	}
	return ret, &resource.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// applicationKeyScopesProfileKey is the resource-profile field carrying a
// credential's provider-granted scopes.
//
// The name is deliberately generic rather than "datadog_scopes" or
// "application_key_scopes". Resource.Profile is free-form, this connector is
// the first V2 credential-issuance implementation, and whatever it picks
// becomes the de-facto convention for the connectors that follow. A consumer
// should be able to read one field to learn what a synced credential is
// allowed to do without knowing which provider minted it, and per-provider
// prefixes would force exactly the special-casing that defeats. It also
// matches this repo's existing profile naming, which is unprefixed
// (userResource uses first_name, login, user_id).
const applicationKeyScopesProfileKey = "scopes"

// applicationKeyProfileOptions returns the resource options carrying an
// application key's scopes, or nothing when Datadog did not report them.
//
// The representation is chosen so a consumer can tell three provider states
// apart using only two profile states, without a type switch:
//
//   - Datadog did not report scopes (nil): the profile key is ABSENT. Emitting
//     an empty list here would assert the key is unscoped, which the response
//     never said, and that is the one error a consumer cannot detect.
//   - Datadog reported an unscoped key (explicit null, or an empty list): the
//     key is present and EMPTY. That positively states "no scope restrictions
//     -- this key carries its owner's full permissions", which is a fact, not
//     missing data.
//   - Datadog reported scopes: the key is present and holds them.
//
// So the value is always a list when present, never null. Reserving absence
// for "not reported" keeps the distinction that matters, and reserving null
// for nothing avoids a key whose type varies between resources -- Profile is
// rendered generically, and a field that is sometimes null and sometimes an
// array is a burden on every reader of it.
func applicationKeyProfileOptions(scopes *[]string) []resource.ResourceOption {
	if scopes == nil {
		return nil
	}
	// structpb rejects []string outright ("proto: invalid type: []string"), so
	// the list has to be widened element by element.
	values := make([]interface{}, 0, len(*scopes))
	for _, scope := range *scopes {
		values = append(values, scope)
	}
	return []resource.ResourceOption{
		resource.WithResourceProfile(map[string]interface{}{
			applicationKeyScopesProfileKey: values,
		}),
	}
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
	var scopes *[]string
	if attrs != nil {
		if attrs.Name != nil {
			name = *attrs.Name
		}
		scopes = client.ScopesFromNullableList(attrs.GetScopesOk())
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
	// Scopes ride on the resource profile: SecretTrait has no scopes field.
	// This is safe to set alongside the secret trait because NewSecretResource
	// appends WithSecretTrait after the caller's options, and
	// syncSecretTraitToResource only copies a trait profile up when the
	// resource has none -- so the profile set here is never clobbered.
	resourceOptions = append(resourceOptions, applicationKeyProfileOptions(scopes)...)
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
